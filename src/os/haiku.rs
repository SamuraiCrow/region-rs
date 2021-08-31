use crate::{Error, Protection, Region, Result};
use libc::{c_uint, c_void, area_info, area_id, area_for,
  B_WRITE_AREA, B_READ_AREA, B_EXECUTE_AREA, B_BAD_VALUE,
  get_area_info, get_next_area_info};
use std::alloc::{Layout, alloc_zeroed, dealloc};

pub struct QueryIter {
  info: *mut area_info,
  cookie: *mut isize
}

impl QueryIter {
  pub fn new(origin: *const (), size: usize) -> Result<QueryIter> {
  	let start: *mut c_void = origin as *mut () as *mut c_void;
    let id: area_id = unsafe{area_for(start)};
    let info: *mut area_info = unsafe{alloc_zeroed(
      Layout::new::<area_info>())
      .cast::<area_info>()};
    let cval = std::ptr::null_mut();
    let status = unsafe{get_area_info(id, info)};
    if status == B_BAD_VALUE || unsafe{(*info).size <= size} {
      Err(Error::UnmappedRegion)
    }
    else
    {
      Ok(
        QueryIter {
          info,
          cookie: cval
        }
      )
    }
  }

  pub fn upper_bound(&self) -> usize {
    unsafe{(*self.info).size}
  }
}

impl Iterator for QueryIter {
  type Item = Result<Region>;

  fn next(&mut self) -> Option<Self::Item> {
    let status = unsafe{get_next_area_info(0, self.cookie, self.info)};
    if status == B_BAD_VALUE {
      return None;
    }

    Some(Ok(Region {
      base: unsafe{(*self.info).address as *const _},
      protection: Protection::from_native(unsafe{(*self.info).protection}),
      shared: unsafe{(*self.info).team==0},
      size: unsafe{(*self.info).size},
      ..Default::default()
    }))
  }
}

impl Drop for QueryIter {
  fn drop(&mut self) {
  	unsafe{dealloc((self.info).cast::<u8>(), Layout::new::<area_info>())};
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
