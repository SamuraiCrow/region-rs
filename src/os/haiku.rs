use crate::{Error, Protection, Region, Result, page, util};
use libc::{c_uint, c_void, area_info, area_id, get_area_info, get_next_area_info,
  set_area_protection, create_area, delete_area, 
  B_WRITE_AREA, B_READ_AREA, B_EXECUTE_AREA, B_BAD_VALUE, B_OK, B_PAGE_SIZE,
  B_ANY_ADDRESS, B_EXACT_ADDRESS, B_NO_LOCK, B_NO_MEMORY, B_BAD_ADDRESS };
use std::io;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, RwLock};
use std::ops::Deref;

// alloc.rs is incompatible with Haiku because of Protection::NONE and must be
//   replaced with something capable of dealing with an AREA_ID return type so
//   it can query the area_info structure and find what it needs.
pub struct Allocation(RwLock<area_info>);

struct KeyType(Mutex<* const ()>);

// no error channel available so it panics at every Poison error encountered
impl PartialEq for KeyType {
  fn eq(&self, other: &Self) -> bool {
    match self.0.lock() {
      Ok(me) => {
      	match other.0.lock() {
      	  Ok(you) => {
      	    return me.deref() == you.deref();
      	  },
      	  Err(_) => panic!("poisoned pointer encountered")
      	}
      },
      Err(_) => panic!("poisoned pointer encountered")
    }
  }
}

impl Eq for KeyType {}

impl Hash for KeyType {
  fn hash<H: Hasher>(&self, state: &mut H) {
    match self.0.lock() {
      Ok(r) => r.deref().hash(state),
      Err(_e) => panic!()
    }
  }
}

static ALLPAGES: &HashMap<KeyType, &Allocation> = &HashMap::new();

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
  let addy = KeyType(Mutex::new(base));
  match ALLPAGES.get(&addy) {
    Some (info) => {
      match info.0.into_inner() {
        Ok(inner) => match set_area_protection(inner.area, protection.to_native()) {
          B_BAD_VALUE => Err(Error::InvalidParameter("bad value")),
          _ => Ok(())
        },
        _ => Err(Error::UnmappedRegion)
      }
    },
    None => Err(Error::UnmappedRegion)
  }
}

#[inline(always)]
pub fn page_size() -> usize {
  return B_PAGE_SIZE;
}


impl Allocation {
  // private helper function
  #[inline(always)]
  fn refresh_info(&self) -> Result<*mut area_info> {
  	match self.0.into_inner() {
      Ok(inner) => match unsafe { get_area_info(inner.area,
          self.0.write().unwrap().deref() as *const area_info as *mut area_info) } {
        B_OK => Ok(&inner as *const area_info as *mut area_info),
        _ => Err(Error::UnmappedRegion)
      },
      _ => Err(Error::UnmappedRegion)
    }
  }

  fn new(my_id: area_id) -> Result<Allocation> {
    let my_alloc = Allocation(RwLock::new(area_info {
      area: my_id,
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
  	}));
  	
  	// initialize actual area_info values here
    match my_alloc.refresh_info() {
      Ok(_v) => Ok(my_alloc), // ignore returned raw pointer
      Err(e) => Err(e)
    }
  }

  #[inline(always)]
  pub fn as_ptr<T>(&self) -> *const T {
  	unsafe {
  	  match self.refresh_info() {
        Ok(info) => return (*info).address.cast(),
        _ => panic!()  // TODO chack this 
  	  }
  	}
  }
  
  #[inline(always)]
  pub fn as_mut_ptr<T>(&self) ->*mut T {
  	unsafe {
      match self.refresh_info() {
        Ok(info) => return (*info).address as *mut T,
        _ => panic!() // TODO check this
      }
  	}
  }
  
  #[inline(always)]
  pub fn as_ptr_range<T>(&self) -> std::ops::Range<*const T> {
  	let range = self.as_range::<T>();
  	(range.start as *const T)..(range.end as *const T)
  }
  
  #[inline(always)]
  pub fn as_mut_ptr_range<T>(&self) -> std::ops::Range<*mut T> {
  	let range = self.as_range::<T>();
  	(range.start as *mut T)..(range.end as *mut T)
  }
  
  #[inline(always)]
  pub fn as_range<T>(&self) -> std::ops::Range<usize> {
    unsafe {
      match self.refresh_info() {
        Ok(info) => return std::ops::Range {
  	      start: (*info).address as usize,
  	      end: ((*info).address as usize).saturating_add((*info).size)
        },
  	    _ => panic!() // TODO check this
  	  }
    }
  }

  #[inline(always)]
  pub fn len(&self) -> usize {
  	match self.refresh_info() { 
  	  Ok(v) => unsafe { (*v).size },
  	  _ => 0 // Is returning 0 length right for an UnmappedRegion error?
  	}
  }
}

impl Drop for Allocation {
  #[inline]
  fn drop(&mut self) {
  	let inner = self.0.get_mut().unwrap();
  	let addy = KeyType(Mutex::new(inner.address as *const c_void as *const ()));
    ALLPAGES.remove(&addy);
    let result = unsafe { delete_area(inner.area) };
    debug_assert!(result == B_OK, "freeing region: B_BAD_ADDRESS");
  }
}

pub fn alloc(size: usize, protection: Protection) -> Result<Allocation> {
  if size == 0 {
    return Err(Error::InvalidParameter("size"));
  }
  
  let size = page::ceil(size as *const ()) as usize;
  
  let address = std::ptr::NonNull::<c_void>::dangling().as_ptr();
  let status = unsafe { create_area(b"region" as *const u8 as *const i8,
    &address as *const *mut c_void as *mut *mut c_void,
    B_ANY_ADDRESS, size, B_NO_LOCK, protection.to_native()) };
  if status < 0 {
  	match status {
      B_BAD_ADDRESS => Err(Error::InvalidParameter("bad address")),
      B_BAD_VALUE => Err(Error::InvalidParameter("bad value")),
      B_NO_MEMORY => Err(Error::SystemCall(io::Error::new(io::ErrorKind::OutOfMemory, "allocation failed"))),
      _ => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "General Error")))
  	}
  } else {  
    // allocation succeeded
    match Allocation::new(status) {
      Ok(mut a) => {
      	let inner = a.0.get_mut().unwrap();
      	let addy = KeyType(Mutex::new(inner.address as *const c_void as *const ()));
        ALLPAGES.insert(addy, &a);
        Ok( a )
      },
      Err(e) => Err(e)
    }
  }
}

pub fn alloc_at<T>(address: *const T, size: usize, protection: Protection) -> Result<Allocation> {
  let (address, size) = util::round_to_page_boundaries(address, size)?;

  let status = unsafe { create_area(b"region" as *const u8 as *const i8, 
      &address as &*const T as *const *const T as *mut *mut T as *mut *mut c_void,
      B_EXACT_ADDRESS, size, B_NO_LOCK, protection.to_native()) };
  if status<0 {
  	match status {
      B_BAD_ADDRESS => Err(Error::InvalidParameter("bad address")),
      B_BAD_VALUE => Err(Error::InvalidParameter("bad value")),
      B_NO_MEMORY => Err(Error::SystemCall(io::Error::new(io::ErrorKind::OutOfMemory, "allocation failed"))),
      _ => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "General Error")))
  	}
  } else {
    // allocation succeeded
    match Allocation::new(status) {
      Ok(mut a) => {
      	let inner = a.0.get_mut().unwrap();
      	let addy = KeyType(Mutex::new(inner.address as *const c_void as *const ()));
        ALLPAGES.insert(addy, &a); 
        Ok ( a )
      }
      Err(e) => Err(e)
    }
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
    let addy = KeyType(Mutex::new(origin));
    let id = match ALLPAGES.get(&addy) {
      Some(v) => v.0.get_mut().unwrap().area, // fetch area_id
      None => {
        return Err(Error::InvalidParameter("Could not find any allocated pages"));
      }
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
