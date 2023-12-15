#[cfg(not(target_feature = "sse"))]
mod non_simd {
	#[derive(Clone, Copy)]
	pub(crate) struct FourF32(f32, f32, f32, f32);
	impl FourF32 {
		#[inline(always)]
		pub(crate) fn new(a: f32, b: f32, c: f32, d: f32) -> Self {
			Self(a, b, c, d)
		}
		#[inline(always)]
		pub(crate) fn from_ints(a: u16, b: u16, c: u16, d: u16) -> Self {
			Self(a as f32, b as f32, c as f32, d as f32)
		}
		#[inline(always)]
		pub(crate) fn hsub(&self) -> Self {
			// _mm_hsub_ps with the second argument zeros
			Self(self.1 - self.0, self.3 - self.2, 0.0, 0.0)
		}
		#[inline(always)]
		pub(crate) fn consuming_sum(&self) -> f32 {
			self.0 + self.1 + self.2 + self.3
		}
		#[inline(always)]
		pub(crate) fn dump(self) -> (f32, f32, f32, f32) {
			(self.3, self.2, self.1, self.0)
		}
	}
	impl std::ops::Div<FourF32> for FourF32 {
		type Output = FourF32;
		#[inline(always)]
		fn div(self, o: FourF32) -> Self {
			Self(self.0 / o.0, self.1 / o.1, self.2 / o.2, self.3 / o.3)
		}
	}
	impl std::ops::Mul<FourF32> for FourF32 {
		type Output = FourF32;
		#[inline(always)]
		fn mul(self, o: FourF32) -> Self {
			Self(self.0 * o.0, self.1 * o.1, self.2 * o.2, self.3 * o.3)
		}
	}
	impl std::ops::Add<FourF32> for FourF32 {
		type Output = FourF32;
		#[inline(always)]
		fn add(self, o: FourF32) -> Self {
			Self(self.0 + o.0, self.1 + o.1, self.2 + o.2, self.3 + o.3)
		}
	}
	impl std::ops::Sub<FourF32> for FourF32 {
		type Output = FourF32;
		#[inline(always)]
		fn sub(self, o: FourF32) -> Self {
			Self(self.0 - o.0, self.1 - o.1, self.2 - o.2, self.3 - o.3)
		}
	}
}
#[cfg(not(target_feature = "sse"))]
pub(crate) use non_simd::*;

#[cfg(target_feature = "sse")]
mod x86_sse {
	#[cfg(target_arch = "x86")]
	use std::arch::x86::*;
	#[cfg(target_arch = "x86_64")]
	use std::arch::x86_64::*;

	#[repr(align(16))]
	struct AlignedFloats([f32; 4]);

	#[derive(Clone, Copy)]
	pub(crate) struct FourF32(__m128);
	impl FourF32 {
		#[inline(always)]
		pub(crate) fn new(a: f32, b: f32, c: f32, d: f32) -> Self {
			Self(unsafe { _mm_set_ps(a, b, c, d) })
		}
		#[inline(always)]
		pub(crate) fn from_ints(a: u16, b: u16, c: u16, d: u16) -> Self {
			unsafe {
				let ints =_mm_set_epi32(a as i32, b as i32, c as i32, d as i32);
				Self(_mm_cvtepi32_ps(ints))
			}
		}
		#[inline(always)]
		pub(crate) fn hsub(&self) -> Self {
			let dummy = unsafe { _mm_setzero_ps() };
			Self(unsafe { _mm_hsub_ps(self.0, dummy) })
		}
		#[inline(always)]
		pub(crate) fn consuming_sum(self) -> f32 {
			let im = unsafe {
				let dummy = _mm_setzero_ps();
				Self(_mm_hadd_ps(self.0, dummy))
			};
			let res = im.dump();
			res.2 + res.3
		}
		#[inline(always)]
		pub(crate) fn dump(self) -> (f32, f32, f32, f32) {
			let mut res = AlignedFloats([0.0; 4]);
			unsafe { _mm_store_ps(&mut res.0[0], self.0) };
			(res.0[3], res.0[2], res.0[1], res.0[0])
		}
	}
	impl std::ops::Div<FourF32> for FourF32 {
		type Output = FourF32;
		#[inline(always)]
		fn div(self, o: FourF32) -> Self {
			Self(unsafe { _mm_div_ps(self.0, o.0) })
		}
	}
	impl std::ops::Mul<FourF32> for FourF32 {
		type Output = FourF32;
		#[inline(always)]
		fn mul(self, o: FourF32) -> Self {
			Self(unsafe { _mm_mul_ps(self.0, o.0) })
		}
	}
	impl std::ops::Add<FourF32> for FourF32 {
		type Output = FourF32;
		#[inline(always)]
		fn add(self, o: FourF32) -> Self {
			Self(unsafe { _mm_add_ps(self.0, o.0) })
		}
	}
	impl std::ops::Sub<FourF32> for FourF32 {
		type Output = FourF32;
		#[inline(always)]
		fn sub(self, o: FourF32) -> Self {
			Self(unsafe { _mm_sub_ps(self.0, o.0) })
		}
	}
}
#[cfg(target_feature = "sse")]
pub(crate) use x86_sse::*;
