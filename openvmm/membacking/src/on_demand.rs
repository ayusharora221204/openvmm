// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! On-demand population of guest RAM from a file, using `userfaultfd`.
//!
//! An [`OnDemandPopulator`] lets a VM run before its RAM backing has been
//! filled from a population source (for example, a snapshot's memory file).
//! Every mapping of the backing in this process is registered with a
//! `userfaultfd`, so the first access to a page that has not been filled waits
//! while the page is read from the source and installed. A background thread
//! fills the remaining pages in order. Once every page is filled, the
//! `userfaultfd` is closed and the backing behaves like any other.
//!
//! Pages are installed through a private view of the whole backing, so each
//! page is read once no matter how many mappings share it. Installing a page
//! only ever fills a missing page, so a page that has already been written is
//! never overwritten.
//!
//! Each mapping of the backing must be registered with [`register_mapping`]
//! before it is accessed: an access through an unregistered mapping would
//! allocate a zero page that the source data can no longer replace. Accesses
//! that bypass this process's mappings (another process, or a device that
//! uses the backing's file descriptor) are not supported during population.
//!
//! If a page cannot be read from the source, the page is poisoned: accesses
//! to it fail rather than observe incorrect contents.

// UNSAFETY: Registering guest RAM mappings with userfaultfd, which allows
// installing data into their missing pages.
#![expect(unsafe_code)]

use crate::mapping_manager::Mappable;
use inspect::Inspect;
use inspect_counters::SharedCounter;
use parking_lot::Mutex;
use sparse_mmap::SparseMapping;
use sparse_mmap::userfaultfd::FaultScope;
use sparse_mmap::userfaultfd::Features;
use sparse_mmap::userfaultfd::Resolved;
use sparse_mmap::userfaultfd::StopEvent;
use sparse_mmap::userfaultfd::Userfaultfd;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;

/// Page states.
const MISSING: u8 = 0;
const LOADING: u8 = 1;
const FILLED: u8 = 2;
/// The page could not be read from the source; accesses to it fail.
const POISONED: u8 = 3;

/// The largest run of pages the background thread fills at once.
const BACKGROUND_FILL_SIZE: usize = 2 * 1024 * 1024;

/// The populators in this process, used to find the populator for a backing
/// when the backing is mapped.
static POPULATORS: Mutex<Vec<Weak<Shared>>> = Mutex::new(Vec::new());

/// Checks whether on-demand population is supported for faults in `scope`.
pub(crate) fn check_support(scope: FaultScope) -> io::Result<()> {
    open_userfaultfd(scope).map(drop)
}

fn open_userfaultfd(scope: FaultScope) -> io::Result<Userfaultfd> {
    Userfaultfd::new(scope, Features::MISSING_SHMEM | Features::POISON).map_err(|err| {
        let context = match err.kind() {
            io::ErrorKind::PermissionDenied => {
                "userfaultfd is not permitted; grant read/write access to /dev/userfaultfd or set vm.unprivileged_userfaultfd=1"
            }
            io::ErrorKind::Unsupported => {
                "userfaultfd does not support shared memory and poisoning (Linux 6.6 or later is required)"
            }
            _ => "failed to open userfaultfd",
        };
        io::Error::new(err.kind(), format!("{context}: {err}"))
    })
}

/// Registers a new mapping of `mappable` for on-demand population, if the
/// backing is being populated. `address` maps `len` bytes of the backing,
/// starting at `file_offset`.
///
/// # Safety
/// The mapping must only be accessed through raw pointers (as guest memory
/// is), and must not have been accessed yet.
pub(crate) unsafe fn register_mapping(
    mappable: &Mappable,
    address: usize,
    len: usize,
    file_offset: u64,
) -> io::Result<()> {
    let Some(shared) = find(mappable)? else {
        return Ok(());
    };
    let Some(active) = shared.active.lock().clone() else {
        return Ok(());
    };
    {
        let mut registrations = shared.registrations.lock();
        // Any overlapping registration is for a mapping that has since been
        // replaced.
        registrations.retain(|r| r.address >= address + len || r.address + r.len <= address);
        registrations.push(Registration {
            address,
            len,
            file_offset,
        });
    }
    // SAFETY: guaranteed by the caller.
    unsafe { active.uffd.register(address, len) }
}

/// Returns whether `mappable` is still being populated.
pub(crate) fn is_populating(mappable: &Mappable) -> io::Result<bool> {
    Ok(find(mappable)?.is_some_and(|shared| shared.active.lock().is_some()))
}

/// Fails if `mappable` is still being populated, for users of the backing
/// that bypass this process's mappings.
pub(crate) fn check_not_populating(mappable: &Mappable) -> io::Result<()> {
    if is_populating(mappable)? {
        return Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            "guest RAM is still being populated on demand",
        ));
    }
    Ok(())
}

fn find(mappable: &Mappable) -> io::Result<Option<Arc<Shared>>> {
    let populators = POPULATORS.lock();
    if populators.is_empty() {
        return Ok(None);
    }
    let file_id = FileId::of(mappable)?;
    Ok(populators
        .iter()
        .filter_map(Weak::upgrade)
        .find(|shared| shared.file_id == file_id))
}

/// Identifies a backing independently of the descriptor used to open it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    fn of(fd: impl AsFd) -> io::Result<Self> {
        let metadata = File::from(fd.as_fd().try_clone_to_owned()?).metadata()?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

/// Populates a RAM backing from a file on demand.
pub(crate) struct OnDemandPopulator {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for OnDemandPopulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDemandPopulator")
            .field("file_id", &self.shared.file_id)
            .finish_non_exhaustive()
    }
}

impl Inspect for OnDemandPopulator {
    fn inspect(&self, req: inspect::Request<'_>) {
        let shared = &*self.shared;
        let state = if shared.failed.load(Ordering::Relaxed) {
            "failed"
        } else if shared.active.lock().is_some() {
            "populating"
        } else {
            "complete"
        };
        req.respond()
            .field("state", state)
            .field("page_count", shared.pages.len())
            .field("remaining_pages", shared.remaining.load(Ordering::Relaxed))
            .merge(&shared.stats);
    }
}

struct Shared {
    file_id: FileId,
    page_size: usize,
    pages: Box<[AtomicU8]>,
    /// The number of pages not yet filled.
    remaining: AtomicUsize,
    /// `None` once population has completed or stopped.
    active: Mutex<Option<Arc<Active>>>,
    /// The registered mappings of the backing.
    registrations: Mutex<Vec<Registration>>,
    /// Faults waiting for pages that are being filled.
    pending: Mutex<Vec<PendingFault>>,
    stop: StopEvent,
    stopping: AtomicBool,
    complete: AtomicBool,
    failed: AtomicBool,
    stats: Stats,
}

struct Active {
    uffd: Userfaultfd,
    source: File,
    /// A mapping of the whole backing, used to install pages.
    view: SparseMapping,
}

#[derive(Debug, Copy, Clone)]
struct Registration {
    address: usize,
    len: usize,
    file_offset: u64,
}

struct PendingFault {
    address: usize,
    page: usize,
}

#[derive(Default, Inspect)]
struct Stats {
    /// Faults reported for missing pages.
    faults: SharedCounter,
    /// Pages filled in response to faults.
    fault_fills: SharedCounter,
    /// Pages filled by the background thread.
    background_fills: SharedCounter,
    /// Discarded pages filled with zeroes.
    zero_fills: SharedCounter,
    /// Faults failed by poisoning the page.
    poisoned: SharedCounter,
}

impl OnDemandPopulator {
    /// Starts populating `len` bytes of `mappable` from `source`, handling
    /// faults in `scope`.
    ///
    /// No mapping of `mappable` may exist yet.
    pub fn new(mappable: &Mappable, source: File, len: u64, scope: FaultScope) -> io::Result<Self> {
        let page_size = SparseMapping::page_size();
        let len = usize::try_from(len).map_err(|_| io::ErrorKind::InvalidInput)?;
        if len == 0 || !len.is_multiple_of(page_size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing size must be a nonzero multiple of the page size",
            ));
        }
        let page_count = len / page_size;

        let uffd = open_userfaultfd(scope)?;
        let view = SparseMapping::new(len)?;
        view.map_file(0, len, mappable, 0, true)?;
        // SAFETY: the view is private to this module and is only used as the
        // destination of userfaultfd operations.
        unsafe { uffd.register(view.as_ptr() as usize, len)? };

        let shared = Arc::new(Shared {
            file_id: FileId::of(mappable)?,
            page_size,
            pages: (0..page_count).map(|_| AtomicU8::new(MISSING)).collect(),
            remaining: AtomicUsize::new(page_count),
            active: Mutex::new(Some(Arc::new(Active { uffd, source, view }))),
            registrations: Mutex::new(Vec::new()),
            pending: Mutex::new(Vec::new()),
            stop: StopEvent::new()?,
            stopping: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            stats: Stats::default(),
        });

        {
            let mut populators = POPULATORS.lock();
            populators.retain(|p| p.strong_count() > 0);
            populators.push(Arc::downgrade(&shared));
        }

        // On failure, dropping `this` stops any thread already started.
        let mut this = Self {
            shared,
            threads: Vec::new(),
        };
        let threads: [(&str, fn(&Shared, &Active)); 2] = [
            ("guest-ram-faults", Shared::run_faults),
            ("guest-ram-fill", Shared::run_fill),
        ];
        for (name, run) in threads {
            let shared = this.shared.clone();
            let active = shared.active.lock().clone().expect("population is active");
            let thread = std::thread::Builder::new()
                .name(name.into())
                .spawn(move || run(&shared, &active))?;
            this.threads.push(thread);
        }
        Ok(this)
    }

    /// Returns whether population has not completed.
    pub fn is_pending(&self) -> bool {
        self.shared.active.lock().is_some()
    }
}

impl Drop for OnDemandPopulator {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Relaxed);
        self.shared.stop.signal();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        self.shared.finish();
    }
}

impl Shared {
    /// Handles faults until population completes or is stopped.
    fn run_faults(&self, active: &Active) {
        let mut buf = vec![0; self.page_size];
        loop {
            match active.uffd.wait(&self.stop) {
                Ok(true) => {}
                Ok(false) => break,
                Err(err) => return self.fatal(err),
            }
            loop {
                match active.uffd.read_fault() {
                    Ok(Some(fault)) => self.handle_fault(active, &mut buf, fault.address),
                    Ok(None) => break,
                    Err(err) => return self.fatal(err),
                }
            }
        }
        if self.complete.load(Ordering::Acquire) && !self.stopping.load(Ordering::Relaxed) {
            tracing::info!(
                pages = self.pages.len(),
                fault_fills = self.stats.fault_fills.get(),
                background_fills = self.stats.background_fills.get(),
                "guest RAM population complete"
            );
            // Closing the userfaultfd (once the background thread also exits)
            // unregisters every mapping.
            self.finish();
        }
    }

    /// Fills missing pages in order until all are filled.
    fn run_fill(&self, active: &Active) {
        let max_pages = (BACKGROUND_FILL_SIZE / self.page_size).max(1);
        let mut buf = vec![0; max_pages * self.page_size];
        let mut page = 0;
        while page < self.pages.len() {
            if self.stopping.load(Ordering::Relaxed) || self.failed.load(Ordering::Relaxed) {
                return;
            }
            if !self.claim(page) {
                page += 1;
                continue;
            }
            let first = page;
            page += 1;
            while page < self.pages.len() && page - first < max_pages && self.claim(page) {
                page += 1;
            }
            self.fill(active, &mut buf, first, page - first);
            self.stats.background_fills.add((page - first) as u64);
        }
    }

    fn handle_fault(&self, active: &Active, buf: &mut [u8], address: usize) {
        self.stats.faults.increment();
        let address = address & !(self.page_size - 1);
        let Some(page) = self.page_for(address) else {
            // This should not happen, since every registered mapping is
            // recorded. Fail the access rather than guess its contents.
            tracelimit::error_ratelimited!(address, "guest RAM fault at an unknown address");
            self.poison(active, address);
            return;
        };
        loop {
            match self.pages[page].load(Ordering::Acquire) {
                MISSING => {
                    if !self.claim(page) {
                        continue;
                    }
                    self.fill(active, buf, page, 1);
                    self.stats.fault_fills.increment();
                    if self.pages[page].load(Ordering::Acquire) == POISONED {
                        self.poison(active, address);
                    }
                }
                LOADING => {
                    let mut pending = self.pending.lock();
                    // Recheck under the lock, since `fill` updates the state
                    // before waking pending faults.
                    if self.pages[page].load(Ordering::Acquire) != LOADING {
                        continue;
                    }
                    pending.push(PendingFault { address, page });
                    return;
                }
                FILLED => {
                    // Either the fault raced with filling the page, or the
                    // page has since been discarded. Discarded RAM reads as
                    // zero.
                    match active
                        .uffd
                        .zeropage(self.view_address(active, page), self.page_size)
                    {
                        Ok(Resolved::All) => self.stats.zero_fills.increment(),
                        Ok(Resolved::AlreadyPresent { .. }) => {}
                        Err(err) => {
                            tracelimit::error_ratelimited!(
                                error = &err as &dyn std::error::Error,
                                address,
                                "failed to zero discarded guest RAM"
                            );
                            self.poison(active, address);
                        }
                    }
                }
                _ => self.poison(active, address),
            }
            break;
        }
        self.wake(active, address);
    }

    /// Fills `count` pages starting at `first`, which must have been claimed,
    /// and wakes faults waiting for them.
    fn fill(&self, active: &Active, buf: &mut [u8], first: usize, count: usize) {
        let offset = first * self.page_size;
        let buf = &mut buf[..count * self.page_size];
        let state = match self.read_and_install(active, buf, offset) {
            Ok(()) => FILLED,
            Err(err) => {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    offset,
                    len = buf.len(),
                    "failed to populate guest RAM; accesses to the affected pages will fail"
                );
                self.failed.store(true, Ordering::Relaxed);
                POISONED
            }
        };
        let pages = &self.pages[first..first + count];
        for page in pages {
            page.store(state, Ordering::Release);
        }
        if state == FILLED && self.remaining.fetch_sub(count, Ordering::AcqRel) == count {
            self.complete.store(true, Ordering::Release);
            self.stop.signal();
        }
        self.pending.lock().retain(|fault| {
            if (first..first + count).contains(&fault.page) {
                self.wake(active, fault.address);
                false
            } else {
                true
            }
        });
    }

    /// Reads `buf.len()` bytes at `offset` from the source and installs them
    /// into the backing.
    fn read_and_install(&self, active: &Active, buf: &mut [u8], offset: usize) -> io::Result<()> {
        active.source.read_exact_at(buf, offset as u64)?;
        let address = active.view.as_ptr() as usize + offset;
        let mut done = 0;
        while done < buf.len() {
            match active.uffd.copy(address + done, &buf[done..])? {
                Resolved::All => break,
                Resolved::AlreadyPresent { installed } => {
                    // The page was written through a mapping that bypassed
                    // population. Keep it, since it is newer than the source.
                    tracelimit::warn_ratelimited!(
                        offset = offset + done + installed,
                        "guest RAM page populated outside of on-demand population"
                    );
                    done += installed + self.page_size;
                }
            }
        }
        Ok(())
    }

    fn claim(&self, page: usize) -> bool {
        self.pages[page]
            .compare_exchange(MISSING, LOADING, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Returns the backing page mapped at `address`.
    fn page_for(&self, address: usize) -> Option<usize> {
        let registrations = self.registrations.lock();
        let r = registrations
            .iter()
            .find(|r| address.wrapping_sub(r.address) < r.len)?;
        let offset = usize::try_from(r.file_offset).ok()? + (address - r.address);
        let page = offset / self.page_size;
        (page < self.pages.len()).then_some(page)
    }

    fn view_address(&self, active: &Active, page: usize) -> usize {
        active.view.as_ptr() as usize + page * self.page_size
    }

    fn poison(&self, active: &Active, address: usize) {
        match active.uffd.poison(address, self.page_size) {
            Ok(_) => self.stats.poisoned.increment(),
            Err(err) => tracelimit::error_ratelimited!(
                error = &err as &dyn std::error::Error,
                address,
                "failed to poison guest RAM"
            ),
        }
    }

    fn wake(&self, active: &Active, address: usize) {
        if let Err(err) = active.uffd.wake(address, self.page_size) {
            tracelimit::error_ratelimited!(
                error = &err as &dyn std::error::Error,
                address,
                "failed to wake guest RAM fault"
            );
        }
    }

    /// Handles a failure to receive faults. Pending and future faults stay
    /// blocked until the populator is dropped, rather than observe unfilled
    /// pages.
    fn fatal(&self, err: io::Error) {
        tracing::error!(
            error = &err as &dyn std::error::Error,
            "failed to receive guest RAM faults; guest RAM accesses will hang"
        );
        self.failed.store(true, Ordering::Relaxed);
    }

    /// Ends population. The userfaultfd is closed, unregistering every
    /// mapping, once no thread is using it.
    fn finish(&self) {
        let active = self.active.lock().take();
        POPULATORS
            .lock()
            .retain(|p| p.strong_count() > 0 && !std::ptr::eq(p.as_ptr(), self));
        drop(active);
    }
}
