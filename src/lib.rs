//! Brave little `no_std` HTTP web server :)
//#![cfg_attr(not(test), no_std)]
#![feature(asm)]

use ip::AddressV4;
use std::convert::TryInto;

mod http;
mod ip;

pub use http::{ParseError, Request, Response};

#[repr(u64)]
enum Syscalls {
    Read = 0,
    Write = 1,
    Socket = 41,
    Accept = 43,
    Shutdown = 48,
    Bind = 49,
    Listen = 50,
}

fn syscall_ret(rax: i64) -> Result<u64, u64> {
    if rax < -1 && rax > -4096 {
        Err(-rax as u64)
    } else {
        Ok(rax as u64)
    }
}

pub struct Socket {
    fd: u64,
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { self.sys_shutdown(2) }.unwrap();
    }
}

impl Socket {
    pub fn bind_and_listen<Address: TryInto<AddressV4>>(address: Address) -> Result<Socket, ()> {
        // TODO: error handling
        let address = address.try_into().map_err(|_| ())?;

        let socket = unsafe { Socket::sys_socket() }.unwrap();
        unsafe { socket.sys_bind(&address) }.unwrap();
        unsafe { socket.sys_listen(64) }.unwrap();

        Ok(socket)
    }

    pub fn accept(&self) -> Result<(Socket, AddressV4), ()> {
        let mut peer = AddressV4::empty();
        let client = unsafe { self.sys_accept(&mut peer) }.unwrap();

        Ok((client, peer))
    }
}

impl Socket {
    unsafe fn sys_socket() -> Result<Socket, u64> {
        let mut rax = Syscalls::Socket as i64;
        let family: u64 = 2; // AF_INET
        let kind: u64 = 1; // stream
        let protocol: u64 = 0; // idk what this is

        asm!(
            "syscall",
            in("rdi") family,
            in("rsi") kind,
            in("rdx") protocol,
            inlateout("rax") rax,
        );

        syscall_ret(rax).map(|fd| Socket { fd })
    }

    unsafe fn sys_bind(&self, address: &AddressV4) -> Result<(), u64> {
        let mut rax = Syscalls::Bind as i64;
        let fd = self.fd;
        let address_ptr = address as *const AddressV4;
        let address_len = 16_u64;

        asm!(
            "syscall",
            in("rdi") fd,
            in("rsi") address_ptr as u64,
            in("rdx") address_len,
            inlateout("rax") rax,
        );

        syscall_ret(rax).map(|_| ())
    }

    unsafe fn sys_listen(&self, backlog: u64) -> Result<(), u64> {
        let mut rax = Syscalls::Listen as i64;
        let fd = self.fd;

        asm!(
            "syscall",
            in("rdi") fd,
            in("rsi") backlog,
            inlateout("rax") rax,
        );

        syscall_ret(rax).map(|_| ())
    }

    unsafe fn sys_shutdown(&self, how: u64) -> Result<(), u64> {
        let mut rax = Syscalls::Shutdown as i64;
        let fd = self.fd;

        asm!(
            "syscall",
            in("rdi") fd,
            in("rsi") how,
            inlateout("rax") rax,
        );

        if rax < -1 {
            Err(-rax as u64)
        } else {
            Ok(())
        }
    }

    unsafe fn sys_accept(&self, peer_address: &mut AddressV4) -> Result<Socket, u64> {
        let mut rax = Syscalls::Accept as i64;
        let fd = self.fd;
        let address_ptr = peer_address;
        let mut address_length: u64 = core::mem::size_of::<AddressV4>() as u64;
        let address_length_ptr = &mut address_length as *mut u64;

        asm!(
            "syscall",
            in("rdi") fd,
            in("rsi") address_ptr,
            in("rdx") address_length_ptr,
            inlateout("rax") rax,
        );

        // TODO: check address_length

        syscall_ret(rax).map(|fd| Socket { fd })
    }

    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, ()> {
        let mut rax = Syscalls::Read as i64;
        let fd = self.fd;
        let buffer_ptr = buffer.as_mut_ptr();
        let count = buffer.len() as u64;

        unsafe {
            asm!(
            "syscall",
            in("rdi") fd,
            in("rsi") buffer_ptr,
            in("rdx") count,
            inlateout("rax") rax,
            );
        }

        // TODO: error handling
        syscall_ret(rax).map(|read| read as usize).map_err(|_| ())
    }

    pub fn write(&self, data: &[u8]) -> Result<usize, ()> {
        let mut rax = Syscalls::Write as i64;
        let fd = self.fd;
        let buffer_ptr = data.as_ptr();
        let count = data.len();

        unsafe {
            asm!(
            "syscall",
            in("rdi") fd,
            in("rsi") buffer_ptr,
            in("rdx") count,
            inlateout("rax") rax,
            );
        }

        // TODO: error handling
        syscall_ret(rax)
            .map(|written| written as usize)
            .map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {}
