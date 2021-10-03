//! Brave little `no_std` HTTP web server :)
//#![cfg_attr(not(test), no_std)]
#![feature(asm)]

use ip::AddressV4;

mod ip;

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

struct Socket {
    fd: u64,
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { self.sys_shutdown(2) }.unwrap();
    }
}

impl Socket {
    pub fn bind_and_listen(address: &AddressV4) -> Result<Socket, ()> {
        let socket = unsafe { Socket::sys_socket() }.unwrap();
        unsafe { socket.sys_bind(address) }.unwrap();
        unsafe { socket.sys_listen(64) }.unwrap();

        Ok(socket)
    }

    pub fn accept(&self) -> Result<Stream, ()> {
        let mut peer = Box::new(AddressV4::empty());
        let stream = unsafe { self.sys_accept(&mut peer) }.unwrap();

        dbg!(peer);

        Ok(stream)
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

    unsafe fn sys_accept(&self, peer_address: &mut AddressV4) -> Result<Stream, u64> {
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

        syscall_ret(rax).map(|fd| Stream { fd })
    }
}

pub struct Stream {
    fd: u64,
}

impl Stream {
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

        syscall_ret(rax).map(|read| read as usize).map_err(|_| ())
    }

    pub fn write(&self, _data: &[u8]) -> Result<(), ()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Shutdown;

    use crate::ip::AddressV4;
    use crate::Socket;

    #[test]
    fn open_socket() {
        let address = AddressV4::parse("127.0.0.1:0").unwrap();
        Socket::bind_and_listen(&address).unwrap();
    }

    #[test]
    fn accept_stream() {
        let address = AddressV4::parse("127.0.0.1:12403").unwrap();
        let socket = Socket::bind_and_listen(&address).unwrap();
        let mut client = std::net::TcpStream::connect("127.0.0.1:12403").unwrap();
        client.set_nonblocking(true).unwrap();

        let stream = socket.accept().unwrap();
        client.write(&[13, 37]);
        client.flush();
        client.shutdown(Shutdown::Both);

        let mut buffer = [0; 1024];
        while let Ok(read) = stream.read(&mut buffer) {
            if read == 0 {
                break;
            }

            assert_eq!(buffer[0..2], [13, 37]);
        }
    }
}
