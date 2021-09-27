use crate::{Error, Protection, Region, Result};
use libc::{c_uint, c_void, area_info, area_id, area_for, thread_info, team_id,
  B_WRITE_AREA, B_READ_AREA, B_EXECUTE_AREA, B_BAD_VALUE, B_OK, B_PAGE_SIZE,
  get_area_info, get_next_area_info, get_thread_info, find_thread,
  malloc, free};

pub struct QueryIter {
  info: *mut area_info,
  cookie: *mut isize,
  id: team_id,
  my_size: usize
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
    let info: *mut area_info = unsafe{ malloc(std::mem::size_of::<area_info>()) as *mut area_info };
    let cval = std::ptr::null_mut();
    let status = unsafe{ get_area_info(area_id, info) };
    if status == B_BAD_VALUE {
      return Err(Error::UnmappedRegion);
    }
    Ok(QueryIter {
      info,
      cookie: cval,
      id: id_team,
      my_size: size
    })
  }

  pub fn upper_bound(&self) -> usize {
    //unsafe{ (*self.info).size }
    self.my_size
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
  	unsafe { free(self.info as *mut c_void) };
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
