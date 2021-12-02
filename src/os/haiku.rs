use crate::{Error, Protection, Region, Result, util};
use libc::{c_uint, c_void, area_info, area_id, area_for, thread_info,
  B_WRITE_AREA, B_READ_AREA, B_EXECUTE_AREA, B_BAD_VALUE, B_OK, B_PAGE_SIZE,
  get_area_info, get_next_area_info, get_thread_info, find_thread, team_id,
  set_area_protection, create_area, delete_area,
  B_ANY_ADDRESS, B_EXACT_ADDRESS, B_NO_LOCK, B_NO_MEMORY, B_ERROR, B_BAD_ADDRESS };
use std::io;

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

pub unsafe fn alloc(base: *const (), size: usize, protection: Protection) -> Result<*const ()> {
  // align base (tup.0) and size (tup.1)
  let tup = match util::round_to_page_boundaries(base, size) {
    Err(e) => return Err(e),
    Ok(t) => t,
  };

  // allocate at fixed address if requested
  let id = if base.is_null() {
    let mut addr = tup.0 as *mut () as *mut c_void;
    create_area(b"region" as *const u8 as *const i8, std::ptr::addr_of_mut!(addr),
      B_ANY_ADDRESS, tup.1, B_NO_LOCK, protection.to_native())
  } else {
     let mut addr = tup.0 as *mut () as *mut c_void;
     create_area(b"region" as *const u8 as *const i8, std::ptr::addr_of_mut!(addr), 
       B_EXACT_ADDRESS, tup.1, B_NO_LOCK, protection.to_native())
  };

  // process errors
  match id {
    B_BAD_ADDRESS => Err(Error::InvalidParameter("bad address")),
    B_BAD_VALUE => Err(Error::InvalidParameter("bad value")),
    B_NO_MEMORY => Err(Error::SystemCall(io::Error::new(io::ErrorKind::OutOfMemory, "allocation failed"))),
    B_ERROR => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "General Error"))),
    // return address
    _ => {
      let info: *mut area_info = libc::malloc(std::mem::size_of::<area_info>()) as *mut area_info;
      match get_area_info(id, info) {
        B_BAD_VALUE => {
          libc::free(info as *mut c_void);
          Err(Error::InvalidParameter("B_BAD_VALUE"))
        },
        B_OK => {
          let ret = (*info).address;
          libc::free(info as *mut c_void);
          return Ok(ret as *mut () as *const () );
        },
        _ => {
          libc::free(info as *mut c_void);
          Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "Unknown Error")))
        }
      }
    }
  }
}

pub unsafe fn free(base: *const (), _size: usize) -> Result<()> {
  let id = area_for(base as *mut () as *mut c_void);
  match id {
    B_ERROR => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "Cannot Find Address"))),
    _ => {
      match delete_area(id) {
        B_ERROR => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "Cannot Deallocate"))),
        _ => Ok(())
      }
    }
  }
}

pub unsafe fn protect(base: *const (), _size: usize, protection: Protection) -> Result<()> {
  let id = area_for(base as *mut () as *mut c_void);
  match id {
    B_ERROR => Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "Address Unfound"))),
    _ => {
      match set_area_protection(id, protection.to_native()) {
        B_BAD_VALUE => Err(Error::InvalidParameter("B_BAD_VALUE")),
        _ => Ok(())
      }
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
  info: *mut area_info,
  cookie: *mut isize,
  id: team_id,
  upper_bound: usize
}

impl QueryIter {
  pub fn new(origin: *const (), size: usize) -> Result<QueryIter> {
    let start: *mut c_void = origin as *mut () as *mut c_void;
    let end = (origin as usize).saturating_add(size);
    let area_id: area_id = unsafe{ area_for(start) };
    if area_id == B_ERROR {
      return Err(Error::UnmappedRegion);
    }
    let id_thread = unsafe { find_thread(std::ptr::null_mut()) };
    let info_thread = unsafe { libc::malloc(std::mem::size_of::<thread_info>()) as *mut thread_info };
    match unsafe { get_thread_info(id_thread, info_thread) } {
      B_OK => {},
      _ => {
      	unsafe { libc::free(info_thread as *mut c_void) };
      	return Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "thread_info failed")));
      }
    }
    let info: *mut area_info = unsafe{ libc::malloc(std::mem::size_of::<area_info>()) as *mut area_info };
    let cval = std::ptr::null_mut();
    match unsafe{ get_area_info(area_id, info) } {
      B_OK => {
      	let id_team = unsafe { (*info_thread).team };
      	unsafe { libc::free(info_thread as *mut c_void) };      	
      	Ok(QueryIter {
          info,
          cookie: cval,
          id: id_team,
          upper_bound: end as usize
        }) 
      },
      _ => {
      	unsafe { libc::free(info_thread as *mut c_void) };
        unsafe { libc::free(info as *mut c_void) };
        Err(Error::SystemCall(io::Error::new(io::ErrorKind::Other, "area_info failed")))
      }
    }
  }

  pub fn upper_bound(&self) -> usize {
    self.upper_bound
  }
}

impl Iterator for QueryIter {
  type Item = Result<Region>;

  fn next(&mut self) -> Option<Self::Item> {
    let status = unsafe { get_next_area_info(0, self.cookie, self.info) };
    if status != B_OK {
      return None;
    }

    Some(Ok(Region {
      base: unsafe { (*self.info).address as *const _ },
      protection: Protection::from_native(unsafe { (*self.info).protection } ),
      shared: unsafe { (*self.info).team == self.id },
      size: unsafe { (*self.info).size },
      ..Default::default()
    }))
  }
}

impl Drop for QueryIter {
  fn drop(&mut self) {
  	unsafe { libc::free(self.info as *mut c_void) };
  }
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

#[cfg(test)]
mod tests {
  use super::*;

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
