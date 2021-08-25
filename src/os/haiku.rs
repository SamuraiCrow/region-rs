use crate::{Error, Protection, Region, Result};
use libc::{c_uint, area_info, area_id, B_WRITE_AREA, B_READ_AREA, B_EXECUTE_AREA, B_BAD_VALUE,
	delete_area, get_area_info, get_next_area_info};

pub struct QueryIter {
  info: *mut area_info,
  cookie: *mut isize,
  id: area_id
}

impl QueryIter {
  pub fn new(_origin: *const (), _size: usize) -> Result<QueryIter> {
  
  	let id: area_id = unsafe{std::mem::zeroed()};
  	let info: *mut area_info = unsafe{std::mem::zeroed()};
  	let cval = std::ptr::null_mut();
  	let status = unsafe{get_area_info(id, info)};
  	match status {
  	  B_BAD_VALUE => {
	  	Err(Error::UnmappedRegion)
  	  }
	  _ => Ok( QueryIter {
    	info,
    	cookie: cval,
    	id})
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
      shared: false, // TODO: UPDATE THIS TO A REAL VALUE
      size: unsafe{(*self.info).size},
      ..Default::default()
    }))
  }
}

impl Drop for QueryIter {
  fn drop(&mut self) {
    unsafe { delete_area(self.id); }
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
