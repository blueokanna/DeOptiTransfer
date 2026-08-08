use core::f64::consts::LN_2;

pub fn dlog(x: f64) -> f64 {
    let mut e: i32 = 0;
    let mut m = x;
    while m >= 1.5 {
        m /= 2.0;
        e += 1;
    }
    while m < 0.75 {
        m *= 2.0;
        e -= 1;
    }
    let z = (m - 1.0) / (m + 1.0);
    let z2 = z * z;
    let mut term = z;
    let mut sum = 0.0;
    let mut n = 1;
    while n <= 21 {
        sum += term / (n as f64);
        term *= z2;
        n += 2;
    }
    (e as f64) * LN_2 + 2.0 * sum
}
