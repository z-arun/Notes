8mod_timer(timer, expires) is equivalent to:
del_timer(timer);
timer->expires = expires;
add_timer(timer);
--------------------------------------------------------------.......

root@beaglebone:/boot# ls
config-4.19.94-ti-r42      SOC.sh                     uEnv.txt
dtbs                       System.map-4.19.94-ti-r42  vmlinuz-4.19.94-ti-r42
initrd.img-4.19.94-ti-r42  uboot


----------------------------------------------------------------------------------

The kernel ring buffer is line buffered, which means it's not flushed until it encounters a newline. Add a \n to the end of your printk strings:

All printk() messages are printed to the kernel log buffer, which is a ring buffer exported to userspace through /dev/kmsg. The usual way to read it is using dmesg.

------------------------------------------------------------------------------
Interrupt controller:
The IC hw is connected to all the peripherals (multiplexes the interrupt lines), it collected all the interrupts from all these peripherals and send appropriate sognal to the cpu core
also it groups different interrupt linues together and based on priority it signals the cpu core.
IC can also disale some interrupt lines temporarly.

IRQ - interrupt request.

top halves  -> for fast operation
bottom halves -> for more processing of data.

-------------------------------------------------------------------------------

request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
	    const char *name, void *dev)
{
	return request_threaded_irq(irq, handler, NULL, flags, name, dev);
}


/**
 * request_irq - Add a handler for an interrupt line
 * @irq:	The interrupt line to allocate
 * @handler:	Function to be called when the IRQ occurs.
 *		Primary handler for threaded interrupts
 *		If NULL, the default primary handler is installed
 * @flags:	Handling flags
 * @name:	Name of the device generating this interrupt
 * @dev:	A cookie passed to the handler function
 *
 * This call allocates an interrupt and establishes a handler; see
 * the documentation for request_threaded_irq() for details.


--------------------------------------------------------------------------------
/**
 *	free_irq - free an interrupt allocated with request_irq
 *	@irq: Interrupt line to free
 *	@dev_id: Device identity to free
 *
 *	Remove an interrupt handler. The handler is removed and if the
 *	interrupt line is no longer in use by any driver it is disabled.
 *	On a shared IRQ the caller must ensure the interrupt is disabled
 *	on the card it drives before calling this function. The function
 *	does not return until any executing interrupts for this IRQ
 *	have completed.
 *
 *	This function must not be called from interrupt context.
 *
 *	Returns the devname argument passed to request_irq.
 */
const void *free_irq(unsigned int irq, void *dev_id)

--------------------------------------------------------------------------------
handler ::

irq_return fun(int intChannel,void * dev) -> dev to identify th device if line is shared.

--------------------------------------------------------------------------------
interrupt context <-----interrupt handler
process context <------ bottom halves
---
app context.

--------------------------------------------------------------------------------
local_irq_disable();
/* interrupts are disabled .. */
local_irq_enable();

irq_disable();
/* interrupts are disabled .. */
irq_enable();

in_irq() <- top halves -  interrupt handler
in_interrupt <- in process context.

-------------------------------------------------------------------------------------
terrupt handlers run with the current interrupt line disabled on all processors.if  with IRQF_DISABLED run with all other interrupt lines also disabled on the local processor

-------------------------------------------------------------------------------------
bottom halves:::
tasklet (run in interrupt context.) - Two different tasklets can run concurrently on different processors, but two of the same type of tasklet cannot run simultaneously

softirq - fast ,but at compile time . In interrupt context.

workqueue - in process context 

sleep allowed only in workqueue..

---------------------------------------------------------------------------------------
compare tasklet, workqueue,softirq
---------------------------------------------------------------------------------------
kmalloc()
GFP_ATOMIC
Used to allocate memory from interrupt handlers and other code outside of a process context. Never sleeps.

GFP_KERNEL
Normal allocation of kernel memory. May sleep.

GFP_USER
Used to allocate memory for user-space pages; it may sleep.

-----------------------------------------------------------------------------------------------------
The Linux kernel knows about a minimum of three memory zones: DMA-capable memory, normal memory, and high memory

The kmalloc() function guarantees that the pages are physically contiguous (and virtually contiguous).

The vmalloc() function works in a similar fashion to kmalloc(), except it allocates memory that is only virtually contiguous and not necessarily physically contiguous.

{mutex, completion, waitqueuey, signal , spin lock}

________________________________________________________________________

Atomic operation  :
normal operation  : get variable value from memory, perform opertion, write back to memeory . So mutex/semaphore need to be used
atomic operations : all the above 3 operations are done in a single instruction cycle.

2 types
1) bit wise
2) on integer 

#define ATOMIC_INIT(i) { (i) }


atomic64_t etx_global_variable = ATOMIC64_INIT(0);
long atomic64_read(atomic64_t *v);
void atomic64_set(atomic64_t *v, int i);
void atomic64_add(int i, atomic64_t *v);
void atomic64_sub(int i, atomic64_t *v);
void atomic64_inc(atomic64_t *v);
void atomic64_dec(atomic64_t *v);
int atomic64_sub_and_test(int i, atomic64_t *v);
int atomic64_add_negative(int i, atomic64_t *v);
long atomic64_add_return(int i, atomic64_t *v);
long atomic64_sub_return(int i, atomic64_t *v);
long atomic64_inc_return(int i, atomic64_t *v);
long atomic64_dec_return(int i, atomic64_t *v);
int atomic64_dec_and_test(atomic64_t *v);
int atomic64_inc_and_test(atomic64_t *v);
set_bit(long nr, volatile unsigned long * addr) /* atomically set the bit in memory */
clear_bit(long nr, volatile unsigned long * addr) /* atomically clear the bit in memory */
change_bit(long nr, volatile unsigned long * addr) /*  toggle a bit in memory */
test_and_set_bit(long nr, volatile unsigned long * addr) /* set the bit and return its old value */
test_and_clear_bit(long nr, volatile unsigned long * addr) /* clear the bit and return its old value */


    atomic_set(atomic_t *a, int value); /* set the value at memory location a */ 
    atomic_add(int val, atomic_t *a); /*add val to value at memory location a */
    atomic_read(const atomic_t *a); /* read the atomic_t value at a*/
    atomic_inc(atomic_t *a) /* increment the value at a atomically */
    atomic_dec(atomic_t *a) /* decrement the value at a atomically */
    atomic_sub(int val, atomic_t *a) /* subtract the value at a by amount val */ 



spinlock - similar to mutex,but will not sleep , it will just spin.
spinlock_t
spin_lock_init(& spinlock_t)
spin_lock()
spin_unlock()
spin_try_lock()
spin_is_locked()

for multpile bottom halves
spin_lock_bh()
spin_unlock_bh()


for  bottom halves and irq
spin_lock_irq()
spin_unlock_irq()

------------------------
consider 10 threads but only 1 writes to the global var , 9 reads , here spinlock will not be efficient since only one thread is writing , even if the reading threads lock it other reading threads can not enter the critical section.

wread-write spn-lock is the solution for this 
mutiple threads can take read spin lock at same time , but the write lock can be taken only when no read lock is active and read spin lock can be taken only when no write spin lock is active 


here read lock is given more priority::

if more priority is needed for write lock then use seqlock.

------------------------------------------
{waitqueuey, signal }
------------------------------------------
memory barriers:::::::  memory barriers are used to avoid the optimization (usually the optimization causes LOAD and STORE values in a diffrenet order than what is visible in the code )(optimization by compiler and cpu itself) of STORE and LOAD of values from/to memory

eG; variables used by different cores.

rmb() <<- makes sure that, all the LOADS which were needed before this line of code is done before this line 
wmb() <<- makes sure that, all the STORE which were needed before this line of code is done before this line 
mb()  <<- makes sure that, all the STORE/LOAD which were needed before this line of code is done before this line 

-----------------------------------------------

completion  -  complete_all() unlocks all thread waiting for completion but complete() will just unlock the first one, so for each thread we will have to call complete() multiple times.


KERNEL debugging.
--------------
OOPS

[ 1718.397978] Unable to handle kernel NULL pointer dereference at virtual address 00000064

[ 1718.412848] pgd = 2fd19747

[ 1718.417255] [00000064] *pgd=00000000

[ 1718.422159] Internal error: Oops: 805 [#1] PREEMPT SMP ARM

[ 1718.427688] Modules linked in: main(O+) pru_rproc irq_pruss_intc pruss pm33xx wkup_m3_rproc wkup_m3_ipc remoteproc virtio virtio_ring prussv

[ 1718.450438] CPU: 0 PID: 2980 Comm: insmod Tainted: G           O      4.19.94-ti-r42 #1buster

[ 1718.458999] Hardware name: Generic AM33XX (Flattened Device Tree)

[ 1718.465140] PC is at initfun+0x2c/0x34 [main]

[ 1718.469530] LR is at wake_up_klogd+0x7c/0xa8

[ 1718.473819] pc : [<bf16b02c>]    lr : [<c01ac370>]    psr: 600f0113
[ 1718.480111] sp : d98a9d80  ip : d98a9ca8  fp : d98a9d8c
[ 1718.485357] r10: c1506e08  r9 : db3ebf40  r8 : d98a9f38
[ 1718.490604] r7 : 00000000  r6 : c1506e08  r5 : bf16b000  r4 : bf16d000
[ 1718.497159] r3 : 00000000  r2 : 00000014  r1 : c10ed348  r0 : 00000000
[ 1718.503716] Flags: nZCv  IRQs on  FIQs on  Mode SVC_32  ISA ARM  Segment none
[ 1718.510883] Control: 10c5387d  Table: 9b6c4019  DAC: 00000051
[ 1718.516657] Process insmod (pid: 2980, stack limit = 0x0f453b05)
[ 1718.522690] Stack: (0xd98a9d80 to 0xd98aa000)
[ 1718.527071] 9d80: d98a9e04 d98a9d90 c01031ac bf16b00c db3eb280 754b2d89 dfd35d0c c02e817c
[ 1718.535288] 9da0: db3eb380 c02fee24 dc633480 dc001e00 d98a9e04 d98a9dc0 c02fee24 c030d64c
[ 1718.543506] 9dc0: c03001f0 c02ff9d0 00000001 0000000c c01ea50c dc001e00 e262f000 754b2d89
[ 1718.551723] 9de0: 00000002 bf16d000 00000002 dc633480 bf16d000 d98a9f38 d98a9e2c d98a9e08
[ 1718.559941] 9e00: c01ea548 c0103168 d98a9e2c d98a9e18 00000002 00000002 db3ebf00 bf16d000
[ 1718.568157] 9e20: d98a9f14 d98a9e30 c01ecdd0 c01ea4e0 bf16d00c 00007fff bf16d000 c01e9990
[ 1718.576375] 9e40: c03194cc c1506e08 c10eb93c c10eb950 c10eb930 c11d4968 c0e05d2c bf16d130
[ 1718.584591] 9e60: 00000000 bf16d1fc daf6fca8 c01e85b4 bf16d048 c01e84ec c1506e08 c11f68d4
[ 1718.592808] 9e80: d98a9f30 00000f2c d98a9ee4 d98a9e98 00000000 00000000 00000000 00000000
[ 1718.601025] 9ea0: 00000000 00000000 6e72656b 00006c65 00000000 00000000 00000000 00000000
[ 1718.609241] 9ec0: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
[ 1718.617458] 9ee0: 00000000 754b2d89 7fffffff c1506e08 00000000 00000003 0042c7e0 c0101204
[ 1718.625674] 9f00: d98a8000 0000017b d98a9fa4 d98a9f18 c01ed398 c01ea800 7fffffff 00000000
[ 1718.633891] 9f20: 00000003 d98a9f24 d98a9f24 e262f000 00000f2c 00000000 e262f116 e262f2c0
[ 1718.642109] 9f40: e262f000 00000f2c e262fb1c e262fa00 e262f870 00003000 00003100 00000000
[ 1718.650326] 9f60: 00000000 00000000 00000408 00000017 00000018 0000000f 0000000d 00000009
[ 1718.658542] 9f80: 00000000 754b2d89 bd90d400 00000000 00000000 0000017b 00000000 d98a9fa8
[ 1718.666759] 9fa0: c0101000 c01ed2e4 bd90d400 00000000 00000003 0042c7e0 00000000 bed05b58
[ 1718.674975] 9fc0: bd90d400 00000000 00000000 0000017b 011cf1a0 00000000 bed05cd8 00000000
[ 1718.683192] 9fe0: bed05b08 bed05af8 00424e41 b6d03d92 40030030 00000003 00000000 00000000
[ 1718.691448] [<bf16b02c>] (initfun [main]) from [<c01031ac>] (do_one_initcall+0x50/0x294)
[ 1718.699592] [<c01031ac>] (do_one_initcall) from [<c01ea548>] (do_init_module+0x74/0x254)
[ 1718.707726] [<c01ea548>] (do_init_module) from [<c01ecdd0>] (load_module+0x25dc/0x290c)
[ 1718.715771] [<c01ecdd0>] (load_module) from [<c01ed398>] (sys_finit_module+0xc0/0x110)
[ 1718.723726] [<c01ed398>] (sys_finit_module) from [<c0101000>] (ret_fast_syscall+0x0/0x54)
[ 1718.731938] Exception stack(0xd98a9fa8 to 0xd98a9ff0)
[ 1718.737014] 9fa0:                   bd90d400 00000000 00000003 0042c7e0 00000000 bed05b58
[ 1718.745229] 9fc0: bd90d400 00000000 00000000 0000017b 011cf1a0 00000000 bed05cd8 00000000
[ 1718.753444] 9fe0: bed05b08 bed05af8 00424e41 b6d03d92
[ 1718.758523] Code: eb4106e5 e3a03000 e3a02014 e1a00003 (e5832064) 
[ 1718.775567] ---[ end trace 22aa24a61de67dbb ]---_

    



oops happens when the kernel cant perform some operation (eg: null pointer),still the kernel will be able to run 
Methods of debugging 
1) CONFIG_DEBUG_INFO
2) addr2line
3) gdb
4) objdump

}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}

addr2line -e main.o  0x2c <------- This will print the line and c file details, here the last argument is the address we got from the oops message.


}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
gdb main.ko
then in gdb shell : list *(initfun+0x2c)


}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}


use objdump

get the base address of module from /proc/modules

main 20480 1 - Loading 0xbf15b000 (O+)<<---------------------------------------------------here
pru_rproc 28672 0 - Live 0xbf141000
irq_pruss_intc 20480 1 pru_rproc, Live 0xbf12d000
pruss 16384 1 pru_rproc, Live 0xbf11a000
pm33xx 16384 0 - Live 0xbf111000
wkup_m3_ipc 16384 1 pm33xx, Live 0xbf108000
wkup_m3_rproc 16384 1 - Live 0xbf100000
remoteproc 57344 3 pru_rproc,wkup_m3_ipc,wkup_m3_rproc, Live 0xbf0d4000
virtio 16384 1 remoteproc, Live 0xbf0cc000
virtio_ring 28672 1 remoteproc, Live 0xbf0c0000
pruss_soc_bus 16384 0 - Live 0xbf0b8000
usb_f_acm 16384 2 - Live 0xbf0af000
u_serial 20480 3 usb_f_acm, Live 0xbf0a6000
usb_f_ecm 20480 2 - Live 0xbf09c000
usb_f_mass_storage 53248 2 - Live 0xbf087000
uio_pdrv_genirq 16384 0 - Live 0xbf06d000
uio 20480 1 uio_pdrv_genirq, Live 0xbf045000
usb_f_rndis 32768 4 - Live 0xbf036000
u_ether 20480 2 usb_f_ecm,usb_f_rndis, Live 0xbf02d000
libcomposite 65536 18 usb_f_acm,usb_f_ecm,usb_f_mass_storage,usb_f_rndis, Live 0xbf014000
spidev 20480 0 - Live 0xbf000000



root@beaglebone:/home/oops# objdump -dS --adjust-vma=0xbf15b000 main.ko

main.ko:     file format elf32-littlearm


Disassembly of section .text.unlikely:

bf15b000 <init_module>:
bf15b000:       e1a0c00d        mov     ip, sp
bf15b004:       e92dd800        push    {fp, ip, lr, pc}
bf15b008:       e24cb004        sub     fp, ip, #4
bf15b00c:       e52de004        push    {lr}            ; (str lr, [sp, #-4]!)
bf15b010:       ebfffffe        bl      0 <__gnu_mcount_nc>
bf15b014:       e3000000        movw    r0, #0
bf15b018:       e3400000        movt    r0, #0
bf15b01c:       ebfffffe        bl      0 <printk>
bf15b020:       e3a03000        mov     r3, #0
bf15b024:       e3a02014        mov     r2, #20
bf15b028:       e1a00003        mov     r0, r3
bf15b02c:       e5832064        str     r2, [r3, #100]  ; 0x64
bf15b030:       e89da800        ldm     sp, {fp, sp, pc}

bf15b034 <cleanup_module>:
bf15b034:       e1a0c00d        mov     ip, sp
bf15b038:       e92dd800        push    {fp, ip, lr, pc}
bf15b03c:       e24cb004        sub     fp, ip, #4
bf15b040:       e52de004        push    {lr}            ; (str lr, [sp, #-4]!)
bf15b044:       ebfffffe        bl      0 <__gnu_mcount_nc>
bf15b048:       e3000000        movw    r0, #0
bf15b04c:       e3400000        movt    r0, #0
bf15b050:       ebfffffe        bl      0 <printk>
bf15b054:       e89da800        ldm     sp, {fp, sp, pc}


}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
note :: The module need to be compiled against the same kernel to insert , else it will cause "Symbol mismatch"
}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}


KASAN -kernel address sanitizer.

CONFIG_KASAN enables this
KASAN Can detet errors related to dynamic memory allocation at run time
eg: using mem after freeing, mem overflow, mem leak.

eg:

==================================================================
 BUG: KASAN: slab-out-of-bounds in _copy_from_user+0x51/0x90
 Write of size 19 at addr ffff888230c0d4a0 by task bash/879

 CPU: 3 PID: 879 Comm: bash Tainted: G           O      5.4.0-rc5+ #16
 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS ?
\-20190711_202441-buildvm-armv7-10.arm.fedoraproject.org-2.fc31 04/01/2014
 Call Trace:
  dump_stack+0x5b/0x90
  print_address_description.constprop.0+0x16/0x200
  ? _copy_from_user+0x51/0x90
  ? _copy_from_user+0x51/0x90
  __kasan_report.cold+0x1a/0x41
  ? _copy_from_user+0x51/0x90
  kasan_report+0xe/0x20
  check_memory_region+0x130/0x1a0
  _copy_from_user+0x51/0x90
  test_kasan_write+0x11/0x30 [test_kasan]
  proc_reg_write+0x110/0x160
  ? proc_reg_unlocked_ioctl+0x150/0x150
  ? __pmd_alloc+0x150/0x150
  ? __audit_syscall_entry+0x18e/0x1f0
  ? ktime_get_coarse_real_ts64+0x46/0x60
  ? security_file_permission+0x66/0x190
  vfs_write+0xed/0x240
  ksys_write+0xb4/0x150
  ? __ia32_sys_read+0x40/0x40
  ? up_read+0x10/0x70
  ? do_user_addr_fault+0x3da/0x560
  do_syscall_64+0x5e/0x190
  entry_SYSCALL_64_after_hwframe+0x44/0xa9
 RIP: 0033:0x7fe39aa3c150
 Code: 73 01 c3 48 8b 0d 20 6d 2d 00 f7 d8 64 89 01 48 83 c8 ff c3\
 66 0f 1f 44 00 00 83 3d 4d ce 2d 00 00 75 10 b8 01 00 00 00 0f 05\
 <48> 3d 01 f0 ff ff 73 31 c3 48 83 ec 08 e8 ee cb 01 00 48 89 04 24
 RSP: 002b:00007fff5b7839d8 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
 RAX: ffffffffffffffda RBX: 0000000000000011 RCX: 00007fe39aa3c150
 RDX: 0000000000000011 RSI: 00007fe39b366000 RDI: 0000000000000001
 RBP: 00007fe39b366000 R08: 000000000000000a R09: 00007fe39b35c740
 R10: 0000000000000022 R11: 0000000000000246 R12: 00007fe39ad14400
 R13: 0000000000000011 R14: 0000000000000001 R15: 0000000000000000

 Allocated by task 894:
  save_stack+0x1b/0x80
  __kasan_kmalloc.constprop.0+0xc2/0xd0
  0xffffffffc0008022
  do_one_initcall+0x86/0x29f
  do_init_module+0xf8/0x350
  load_module+0x3e57/0x4120
  __do_sys_finit_module+0x162/0x190
  do_syscall_64+0x5e/0x190
  entry_SYSCALL_64_after_hwframe+0x44/0xa9

 Freed by task 614:
  save_stack+0x1b/0x80
  __kasan_slab_free+0x12c/0x170
  kfree+0x90/0x240
  xdr_free_bvec+0x1a/0x30
  xprt_release+0x10a/0x270
  rpc_release_resources_task+0x14/0x70
  __rpc_execute+0x253/0x590
  rpc_async_schedule+0x44/0x70
  process_one_work+0x476/0x760
  worker_thread+0x73/0x680
  kthread+0x18c/0x1e0
  ret_from_fork+0x35/0x40

 The buggy address belongs to the object at ffff888230c0d4a0
  which belongs to the cache kmalloc-16 of size 16
 The buggy address is located 0 bytes inside of
  16-byte region [ffff888230c0d4a0, ffff888230c0d4b0)
 The buggy address belongs to the page:
 page:ffffea0008c30340 refcount:1 mapcount:0
mapping:ffff888236403b80 index:0xffff888230c0d9c0
 flags: 0x200000000000200(slab)
 raw: 0200000000000200 ffffea0008b86700 0000001200000012 ffff888236403b80
 raw: ffff888230c0d9c0 0000000080800079 00000001ffffffff 0000000000000000
 page dumped because: kasan: bad access detected

 Memory state around the buggy address:
  ffff888230c0d380: 00 00 fc fc fb fb fc fc fb fb fc fc fb fb fc fc
  ffff888230c0d400: fb fb fc fc fb fb fc fc fb fb fc fc fb fb fc fc
 >ffff888230c0d480: fb fb fc fc 00 06 fc fc fb fb fc fc 00 00 fc fc
                                   ^
  ffff888230c0d500: 00 00 fc fc 00 00 fc fc 00 00 fc fc 00 00 fc fc
  ffff888230c0d580: 00 00 fc fc 00 00 fc fc 00 00 fc fc 00 00 fc fc
 ==================================================================
>


SLUB / SLAB
_----------_

CONFIG_DEBUG_SLUB

SLUB - this adds buffer over flow poison memory before and after the needed allocated memory.
[poison mem | needed mem | poison mem]

This also helps in debugging mem read before init, mem over flow, mem using after deallocate.


//////////////////

CONFIG_DEBUG_KMEMLEAK

echo scan /sys/kernel/debug/kmemleak
cat /sys/kernel/debug/kmemleak

////////////////
CONFIG_DEBUG_LOCKDEP  --<<<< for detection of dead lock: it will give possibility of circular dependency at run time.
////////////////

dump_stack();  <<----------------This will print how the code reach there ,like how was the flow . This will not desturb the kernel operations.


kmemcheck
kgdb ??????????
DEBUG_PAGEALLOC


IOCTL--------------------------------------
ioctl vs unlocked_ioctl -> ioctl uses BKL which prevents other kernel drivers 
Big Kernel Lock (BKL) -> older implementation for multi core for synchronization - similar to spin lock.

_IOX -< X is only for access 
-------------------------------------------------------------------------------------------------------------------------------
dump_stack() prints the stack trace 


CONFIG_DEBUG_LOCKDEP will print possible dedlocks 
static noinline int thread_b(void *unused)
{
  mutex_lock(&b); pr_info("%s acquired B\n", __func__);
  mutex_lock(&a); pr_info("%s acquired A\n", __func__);

  mutex_unlock(&a);
  mutex_unlock(&b);

  return 0;
}

thread_a acquired A
thread_a acquired B
thread_b acquired B

======================================================
WARNING: possible circular locking dependency detected
4.19.0+ #4 Tainted: G           O
------------------------------------------------------
thread_b/238 is trying to acquire lock:
(ptrval) (a){+.+.}, at: thread_b+0x48/0x90 [locking]

but task is already holding lock:
(ptrval) (b){+.+.}, at: thread_b+0x27/0x90 [locking]

which lock already depends on the new lock.




-----
kprobe
perf tool.
kdump
-----------------------------------------
kgdb
kdb
-----------------------------------------
/proc/sys/kernel/

<img width="696" alt="image" src="https://github.com/user-attachments/assets/afd9dfcb-217e-4a3a-9ce0-01f6e9c13662">

/proc/sys/kernel/watchdog_thresh   <---------

for_each_task
https://github.com/torvalds/linux/blob/master/include/linux/preempt.h
