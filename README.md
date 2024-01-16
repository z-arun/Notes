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
[ 1718.775567] ---[ end trace 22aa24a61de67dbb ]---



oops happens when the kernel cant perform some operation (eg: null pointer),still the kernel will be able to run 
Methods of debugging 
1) CONFIG_DEBUG_INFO
2) addr2line
3) gdb
4) objdump


memeory debugging ::
KASAN

SLUB - this adds buffer over flow poison memory before and after the needed allocated memory.[poison mem | needed mem | poison mem]

kmemcheck
kgdb ??????????
DEBUG_PAGEALLOC
