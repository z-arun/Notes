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

