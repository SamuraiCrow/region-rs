use crate::{Error, Protection, Region, Result, page, util};
use libc::{c_uint, c_void, area_info, area_id, get_area_info, get_next_area_info,
  set_area_protection, create_area, delete_area,
  B_WRITE_AREA, B_READ_AREA, B_EXECUTE_AREA, B_BAD_VALUE, B_OK, B_PAGE_SIZE,
  B_ANY_ADDRESS, B_EXACT_ADDRESS, B_NO_LOCK, B_NO_MEMORY, B_BAD_ADDRESS };
use std::io;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, Arc};
use std::sync::atomic::AtomicPtr;
use lazy_static::lazy_static;

// alloc.rs is incompatible with Haiku because of Protection::NONE and must be
//   replaced with something capable of dealing with an AREA_ID return type so
//   it can query the area_info structure and find what it needs.  Most in-code
//   comments are duplicated from the alloc.rs file and it forms the basis for
//   the Haiku version of the allocation structure and methods.

/// A handle to an owned region of memory.
///
/// This handle does not dereference to a slice, since the underlying memory may
/// have been created with [`Protection::NONE`].
#[derive(Clone)]
pub struct Allocation(Arc<area_id>);

struct KeyType(Arc<AtomicPtr<()> >);

impl PartialEq for KeyType {
  fn eq(&self, other: &Self) -> bool {
    Arc::as_ptr(&self.0) == Arc::as_ptr(&other.0)
  }
}

impl Eq for KeyType {}

impl Hash for KeyType {
  fn hash<H: Hasher>(&self, state: &mut H) {
  	Arc::as_ptr(&self.0).hash(state)
  }
}

lazy_static ! {
  static ref ALLPAGES: Mutex<HashMap<KeyType, Allocation> > = {
    let m = Mutex::new(HashMap::new());
    m
  };
}

impl Protection {
  fn from_native(protection: c_uint) -> Self {
    const MAPPINGS: &[(c_uint, Protection)] = &[
      (B_READ_AREA, Protection::READ),
      (B_WRITE_AREA, Protection::WRITE),
      (B_EXECUTE_AREA, Protection::EXECUTE),
    ];

    MAPPINGS
      .iter()
      .filter(|(flag, _)| protection & *flag == *flag)
      .fold(Protection::NONE, |acc, (_, prot)| acc | *prot)
  }
  
  fn to_native(self) -> c_uint {
    const MAPPINGS: &[(Protection, c_uint)] = &[
      (Protection::READ, B_READ_AREA),
      (Protection::WRITE, B_WRITE_AREA),
      (Protection::EXECUTE, B_EXECUTE_AREA),
    ];

    MAPPINGS
      .iter()
      .filter(|(flag, _)| self & *flag == *flag)
      .fold(0 as u32, |acc, (_, prot)| acc | *prot)
  }
}

pub unsafe fn protect(base: *const (), _size: usize, protection: Protection) -> Result<()> {
  let addy = KeyType(Arc::new(AtomicPtr::new(base as *mut () )));
  match ALLPAGES.lock() {
    Ok(h) => match h.get(&addy) {
      Some(alloc) => match alloc.refresh_info() {
        Ok (info) => {
          if set_area_protection(info.area, protection.to_native()) < B_OK {
            Err(Error::InvalidParameter("bad value"))
          } else {
            Ok(())
          }
        },
        Err(e) => Err(e)
      },
      None => Err(Error::UnmappedRegion)
    },
    _ => Err(Error::UnmappedRegion) 
  }
}

#[inline(always)]
pub fn page_size() -> usize {
  return B_PAGE_SIZE;
}


impl Allocation {
  // private helper function
  #[inline(always)]
  fn refresh_info(&self) -> Result<area_info> {
    let mut info = area_info {
      area: *(self.0),
      address: std::ptr::null_mut() as *mut c_void,
      size: 0,
      name: [0; 32],
      lock: B_NO_LOCK,
      protection: 0,
      ram_size: 0,
      copy_count: 0,
      in_count: 0,
      out_count: 0,
      team: 0
  	};
  	
  	match unsafe { get_area_info(info.area, &mut info) } {
      B_OK => Ok(info),
      _ => Err(Error::UnmappedRegion)
    }
  }

  #[inline(always)]
  fn new(my_id: area_id) -> Result<Allocation> {
    Ok(Allocation(Arc::<area_id>::new(my_id)))
  }
  
  /// Returns a pointer to the allocation's base address.
  ///
  /// The address is always aligned to the operating system's page size.
  #[inline(always)]
  pub fn as_ptr<T>(&self) -> *const T {
    match self.refresh_info() {
      Ok(info) => return info.address.cast(),
      _ => panic!()  // TODO chack this 
  	}
  }
  
  /// Returns a mutable pointer to the allocation's base address.
  #[inline(always)]
  pub fn as_mut_ptr<T>(&self) ->*mut T {
    match self.refresh_info() {
      Ok(info) => return info.address as *mut T,
      _ => panic!() // TODO check this
  	}
  }
  
  /// Returns two raw pointers spanning the allocation's address space.
  ///
  /// The returned range is half-open, which means that the end pointer points
  /// one past the last element of the allocation. This way, an empty allocation
  /// is represented by two equal pointers, and the difference between the two
  /// pointers represents the size of the allocation.
  #[inline(always)]
  pub fn as_ptr_range<T>(&self) -> std::ops::Range<*const T> {
  	let range = self.as_range::<T>();
  	(range.start as *const T)..(range.end as *const T)
  }
  
  /// Returns two mutable raw pointers spanning the allocation's address space.
  #[inline(always)]
  pub fn as_mut_ptr_range<T>(&self) -> std::ops::Range<*mut T> {
  	let range = self.as_range::<T>();
  	(range.start as *mut T)..(range.end as *mut T)
  }
  
  /// Returns a range spanning the allocation's address space.
  #[inline(always)]
  pub fn as_range<T>(&self) -> std::ops::Range<usize> {
    match self.refresh_info() {
      Ok(info) => return std::ops::Range {
        start: info.address as usize,
        end: (info.address as usize).saturating_add(info.size)
      },
  	  _ => panic!() // TODO check this
    }
  }

  /// Returns the size of the allocation in bytes.
  ///
  /// The size is always aligned to a multiple of the operating system's page
  /// size.
  #[inline(always)]
  pub fn len(&self) -> usize {
  	match self.refresh_info() { 
  	  Ok(v) => v.size,
  	  _ => 0 // Is returning 0 length right for an UnmappedRegion error?
  	}
  }
}

impl Drop for Allocation {
  #[inline]
  fn drop(&mut self) {
    match self.refresh_info() {
      Ok(inner) => {
        match ALLPAGES.lock() {
          Ok(mut h) => {
            let mut s = inner.size;
            // clear all dropped pages from hash
            while s >= B_PAGE_SIZE {
              s = s - B_PAGE_SIZE;
              let addy = unsafe { KeyType(Arc::new(AtomicPtr::new( inner.address.offset(s as isize) as *mut () ))) };
              h.remove(&addy);
            }
            // clear area also
            let result = unsafe { delete_area(inner.area) };
            debug_assert!(result == B_OK, "freeing region: B_BAD_ADDRESS");
          },
          _ => panic!("poisoned pointer")
        }
  	  },
  	  _ => panic!("refresh_info() failed during a Drop")
    }
  }
}

/// Allocates one or more pages of memory, with a defined protection.
///
/// This function provides a very simple interface for allocating anonymous
/// virtual pages. The allocation address will be decided by the operating
/// system.
///
/// # Parameters
///
/// - The size may not be zero.
/// - The size is rounded up to the closest page boundary.
///
/// # Errors
///
/// - If an interaction with the underlying operating system fails, an error
/// will be returned.
/// - If size is zero, [`Error::InvalidParameter`] will be returned.
///
/// # Examples
///
/// ```
/// # fn main() -> region::Result<()> {
/// # if cfg!(any(target_arch = "x86", target_arch = "x86_64")) && !cfg!(target_os = "openbsd") {
/// use region::Protection;
/// let ret5 = [0xB8, 0x05, 0x00, 0x00, 0x00, 0xC3u8];
///
/// let memory = region::alloc(100, Protection::READ_WRITE_EXECUTE)?;
/// let slice = unsafe {
///   std::slice::from_raw_parts_mut(memory.as_ptr::<u8>() as *mut u8, memory.len())
/// };
///
/// slice[..6].copy_from_slice(&ret5);
/// let x: extern "C" fn() -> i32 = unsafe { std::mem::transmute(slice.as_ptr()) };
///
/// assert_eq!(x(), 5);
/// # }
/// # Ok(())
/// # }
/// ```
pub fn alloc(size: usize, protection: Protection) -> Result<Allocation> {
  if size == 0 {
    return Err(Error::InvalidParameter("size"));
  }
  match ALLPAGES.lock() {
    Ok(mut h) => {
  
      let size = page::ceil(size as *const ()) as usize;
  
      let address = std::ptr::NonNull::<c_void>::dangling().as_ptr();
      let status = unsafe { create_area(b"region" as *const u8 as *const i8,
        &address as *const *mut c_void as *mut *mut c_void,
        B_ANY_ADDRESS, size, B_NO_LOCK, protection.to_native()) };
      if status < B_OK {
  	    match status {
          B_BAD_ADDRESS => Err(Error::InvalidParameter("bad address")),
          B_BAD_VALUE => Err(Error::InvalidParameter("bad value")),
          B_NO_MEMORY => Err(Error::SystemCall(io::Error::new(io::ErrorKind::OutOfMemory, "allocation failed"))),
          _ => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "General Error")))
  	    }
      } else {
      // allocation succeeded
        match Allocation::new(status) {
          Ok(inner) => {
            match inner.refresh_info() {
              Ok(a) => {
                let mut s = a.size;
                while s >= B_PAGE_SIZE {
                  s = s - B_PAGE_SIZE;
                  let addy = unsafe { KeyType(Arc::new(AtomicPtr::new( a.address.offset(s as isize) as *mut () ))) };
                  h.insert(addy, inner.clone());
                }
                return Ok( inner );
             },
             Err(e) => Err(e)
           }
          },
          Err(e) => Err(e)
        }
      }
    },
    _ => panic!("poisoned pointer")
  }
}

/// Allocates one or more pages of memory, at a specific address, with a defined
/// protection.
///
/// The returned memory allocation is not guaranteed to reside at the provided
/// address. E.g. on Windows, new allocations that do not reside within already
/// reserved memory, are aligned to the operating system's allocation
/// granularity (most commonly 64KB).
///
/// # Implementation
///
/// This function is implemented using `VirtualAlloc` on Windows, and `mmap`
/// with `MAP_FIXED` on POSIX.
///
/// # Parameters
///
/// - The address is rounded down to the closest page boundary.
/// - The size may not be zero.
/// - The size is rounded up to the closest page boundary, relative to the
///   address.
///
/// # Errors
///
/// - If an interaction with the underlying operating system fails, an error
/// will be returned.
/// - If size is zero, [`Error::InvalidParameter`] will be returned.
pub fn alloc_at<T>(address: *const T, size: usize, protection: Protection) -> Result<Allocation> {
  match ALLPAGES.lock() {
    Ok(mut h) => {
      let (address, size) = util::round_to_page_boundaries(address, size)?;

      let status = unsafe { create_area(b"region" as *const u8 as *const i8, 
          &address as &*const T as *const *const T as *mut *mut T as *mut *mut c_void,
          B_EXACT_ADDRESS, size, B_NO_LOCK, protection.to_native()) };
      if status < B_OK {
  	    match status {
          B_BAD_ADDRESS => Err(Error::InvalidParameter("bad address")),
          B_BAD_VALUE => Err(Error::InvalidParameter("bad value")),
          B_NO_MEMORY => Err(Error::SystemCall(io::Error::new(io::ErrorKind::OutOfMemory, "allocation failed"))),
          _ => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "General Error")))
  	    }
      } else {
        // allocation succeeded
        match Allocation::new(status) {
          Ok(inner) => match inner.refresh_info() {
            Ok(a) => {
              let mut s = a.size;
              // add page lookups for each page of allocation to hash
              while s >= B_PAGE_SIZE {
                s = s - B_PAGE_SIZE;
                let addy = unsafe { KeyType(Arc::new(AtomicPtr::new( a.address.offset(s as isize) as *mut () ))) };
                h.insert(addy, inner.clone());
              }
              Ok ( inner )
            },
            Err(e) => Err(e)
          },
          Err(e) => Err(e)
        }
      }
    },
    _ => panic!("poisoned pointer")
  }
}

pub fn lock(base: *const (), size: usize) -> Result<()> {
  match unsafe { libc::mlock(base.cast(), size) } {
    0 => Ok(()),
    _ => Err(Error::SystemCall(io::Error::last_os_error())),
  }
}

pub fn unlock(base: *const (), size: usize) -> Result<()> {
  match unsafe { libc::munlock(base.cast(), size) } {
    0 => Ok(()),
    _ => Err(Error::SystemCall(io::Error::last_os_error())),
  }
}

pub struct QueryIter {
  info: area_info,
  cookie: isize,
}

impl QueryIter {
  pub fn new(origin: *const (), _size: usize) -> Result<QueryIter> {
    let addy = KeyType(Arc::new(AtomicPtr::new(origin as *mut () )));
    let id = match ALLPAGES.lock() {
      Ok(h) => match h.get(&addy) {
        Some(v) => *(v.0), // fetch area_id
        None => return Err(Error::InvalidParameter("Could not find any allocated pages"))
      },
      _ => panic!("poisoned pointer")
    };
    let qi = QueryIter {
      cookie: 0,
      info: area_info {
        area: id,
        address: std::ptr::null_mut() as *mut c_void,
        size: 0,
        name: [0; 32],
        lock: B_NO_LOCK,
        protection: 0,
        ram_size: 0,
        copy_count: 0,
        in_count: 0,
        out_count: 0,
        team: 0
      }
  	};
    match unsafe{ get_area_info(id, &[qi.info] as *const area_info as *mut area_info) } {
      B_OK => Ok( qi ),
      _ => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "area_info failed")))
    }
  }

  #[inline(always)]
  pub fn upper_bound(&self) -> usize {
    self.info.size as usize
  }
}

impl Iterator for QueryIter {
  type Item = Result<Region>;

  fn next(&mut self) -> Option<Self::Item> {
    let status = unsafe { get_next_area_info(0, &[self.cookie] as *const isize as *mut isize,
      &[self.info] as *const area_info as *mut area_info ) };
    if status != B_OK {
      return None;
    }

    Some(Ok(Region {
      base: self.info.address as *const _,
      protection: Protection::from_native(self.info.protection),
      size: self.info.size,
      ..Default::default()
    }))
  }
}

impl Drop for QueryIter {
  fn drop(&mut self) {}
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn alloc_size_is_aligned_to_page_size() -> Result<()> {
    let memory = alloc(1, Protection::NONE)?;
    assert_eq!(memory.len(), page::size());
    Ok(())
  }
  
  #[test]
  fn alloc_rejects_empty_allocation() {
    assert!(matches!(
      alloc(0, Protection::NONE),
      Err(Error::InvalidParameter(_))
    ));
  }

  #[test]
  fn alloc_obtains_correct_properties() -> Result<()> {
    let memory = alloc(1, Protection::READ_WRITE)?;

    let region = crate::query(memory.as_ptr::<()>())?;
    assert_eq!(region.protection(), Protection::READ_WRITE);
    assert!(region.len() >= memory.len());
    assert!(!region.is_guarded());
    assert!(!region.is_shared());
    assert!(region.is_committed());

    Ok(())
  }

  #[test]
  fn alloc_frees_memory_when_dropped() -> Result<()> {
    let base = alloc(1, Protection::READ_WRITE)?.as_ptr::<()>();
    let query = crate::query(base);
    assert!(matches!(query, Err(Error::UnmappedRegion)));
    Ok(())
  }

  #[test]
  fn alloc_can_allocate_unused_region() -> Result<()> {
    let base = alloc(1, Protection::NONE)?.as_ptr::<()>();
    let memory = alloc_at(base, 1, Protection::READ_WRITE)?;
    assert_eq!(memory.as_ptr(), base);
    Ok(())
  }

  #[test]
  fn protection_flags_are_mapped_from_native() {
    let rw = B_READ_AREA | B_WRITE_AREA;
    let rwx = rw | B_EXECUTE_AREA;

    assert_eq!(Protection::from_native(0), Protection::NONE);
    assert_eq!(Protection::from_native(B_READ_AREA), Protection::READ);
    assert_eq!(Protection::from_native(rw), Protection::READ_WRITE);
    assert_eq!(Protection::from_native(rwx), Protection::READ_WRITE_EXECUTE);
  }
}
