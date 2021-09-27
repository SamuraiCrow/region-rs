use crate::{Error, Protection, Region, Result};
use libc::{c_uint, c_void, area_info, area_id, area_for, thread_info,
  B_WRITE_AREA, B_READ_AREA, B_EXECUTE_AREA, B_BAD_VALUE, B_OK, B_PAGE_SIZE,
  get_area_info, get_next_area_info, get_thread_info, find_thread, team_id,
  set_area_protection, create_area, delete_area,
  B_ANY_ADDRESS, B_EXACT_ADDRESS, B_NO_LOCK, B_NO_MEMORY, B_ERROR };
use std::io;

pub fn page_size() -> usize {
  return B_PAGE_SIZE;
}

pub unsafe fn alloc(base: *const (), size: usize, protection: Protection) -> Result<*const ()> {
  let info: *mut area_info = libc::malloc(std::mem::size_of::<area_info>()) as *mut area_info;
  
  let flags = if base.is_null() {
  	B_ANY_ADDRESS
  } else {
    B_EXACT_ADDRESS
  };
  
  let mut addr = base as *mut () as *mut c_void;
  
  let id = create_area(b"\0".as_ptr() as *const i8, std::ptr::addr_of_mut!(addr), 
    flags, size, B_NO_LOCK, protection.to_native());
    match id {
    B_BAD_VALUE => Err(Error::SystemCall(io::Error::last_os_error())),
    B_NO_MEMORY => Err(Error::SystemCall(io::Error::last_os_error())),
    B_ERROR => Err(Error::SystemCall(io::Error::last_os_error())),
    _ => {
      match get_area_info(id, info) {
        B_BAD_VALUE => Err(Error::SystemCall(io::Error::last_os_error())),    
        _ => {
          let ret = (*info).address;
          libc::free(info as *mut c_void);
          return Ok(ret as *mut () as *const () );
        }
      }
    }
  }
}

pub unsafe fn free(base: *const (), _size: usize) -> Result<()> {
  let id = area_for(base as *mut () as *mut c_void);
  match id {
    B_ERROR => Err(Error::SystemCall(io::Error::last_os_error())),
    _ => {
      match delete_area(id) {
        B_ERROR => Err(Error::SystemCall(io::Error::last_os_error())),
        _ => Ok(())        
      }
    }
  }
}

pub unsafe fn protect(base: *const (), _size: usize, protection: Protection) -> Result<()> {
  let id = area_for(base as *mut () as *mut c_void);
  match id {
    B_ERROR => Err(Error::SystemCall(io::Error::last_os_error())),
    _ => {
      match set_area_protection(id, protection.to_native()) {
        B_BAD_VALUE => Err(Error::SystemCall(io::Error::last_os_error())),
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
    let end: *mut c_void = unsafe { start.add(size) };
    let area_id: area_id = unsafe{ area_for(start) };
    if unsafe { area_for(end) } != area_id.clone() {
    	return Err(Error::UnmappedRegion);
    }
    let mut team_info = std::mem::MaybeUninit::<thread_info>::uninit();
    let get_team = unsafe {
      get_thread_info(find_thread(0 as *const i8),
      team_info.as_mut_ptr() ) == B_OK
    };
    let id_team = if get_team {
      let team_info = unsafe { team_info.assume_init() };
      team_info.team
    } else {
     -1
    };
    if !get_team {
      let e=std::io::Error::new(std::io::ErrorKind::Other, "get_thread_info");
      return Err(Error::SystemCall(e));
    }
    let info: *mut area_info = unsafe{ libc::malloc(std::mem::size_of::<area_info>()) as *mut area_info };
    let cval = std::ptr::null_mut();
    let status = unsafe{ get_area_info(area_id, info) };
    if status == B_BAD_VALUE {
      return Err(Error::UnmappedRegion);
    }
    Ok(QueryIter {
      info,
      cookie: cval,
      id: id_team,
      upper_bound: end as usize
    })
  }

  pub fn upper_bound(&self) -> usize {
    self.upper_bound
  }
}

impl Iterator for QueryIter {
  type Item = Result<Region>;

  fn next(&mut self) -> Option<Self::Item> {
    let status = unsafe { get_next_area_info(0, self.cookie, self.info) };
    if status == B_BAD_VALUE {
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
