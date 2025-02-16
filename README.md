![](/assets/school.jpg)
# 目录

[toc]

# 一、基本信息

| 赛题     | [proj289-High-performance-user-mode-file-system](https://github.com/oscomp/proj289-High-performance-user-mode-file-system) |
| -------- | ------------------------------------------------------------ |
| 队伍名称 | 萤火虫                                                       |
| 小组成员 | 尚凡（研一）、杨传江（研一）、谢佳月（大二）                 |
| 项目导师 | 郑昱笙                                                       |
| 校内导师 | 陈莉君                                                       |

# 二、项目简介

&emsp;&emsp;本报告旨在分析并提出对现有 FUSE (Filesystem in Userspace) 文件系统的性能优化方案。FUSE 允许创建用户空间文件系统，这样的设计虽然提供了灵活性，但也引入了额外的开销，特别是在用户态和内核态之间的交互频繁时。本研究通过技术改进，目标是减少这些开销，提高文件系统的效率和响应速度。   
&emsp;&emsp;为此我们希望在bpftime工具的帮助下尽量减少FUSE文件系统在用户态和内核态的不必要切换，并且重写inode管理模块，为此我们设置了这些目标，并在在比赛期间完成所有。 

| 目标                                            | 完成情况 | 目标说明                                                     |
| ----------------------------------------------- | -------- | ------------------------------------------------------------ |
| 目标一：bpftime实现截断用户态系统调用 | 完成100%  | 1、使用bpf_override_return在bpftime用户态模式下截断系统调用       |
| 目标二：fuse文件系统实现                        | 完成100%  | 1、实现create、umtime、getattr、mkdir、readdir、write，read这几个回调函数          |
| 目标三：inode管理                               | 完成100%  | 1、实现inode的增、查、改、删<br />2、fuse回调函数可以成功使用inode管理的接口 |
| 目标四：inode缓存                               | 完成100%   | 1、这里使用哈希表和红黑树共同优化性能，代替缓存      |
| 目标五：inode并发控制                           | 完成100%   | 1、inode数据结构添加互斥锁                                               |
| 目标六：性能检测与调优                          | 完成100%   | 1、开发监控工具来跟踪fuse文件系统的性能<br />2、进行性能测试，以识别当前实现的限制，并基于测试结果调整策略 |
| 目标七：进程通信                            |完成100%   | 1、使用共享内存的方式进行通信<br /> 2、使用futex实现高效的同步机制  <br /> 3、pthread线程机制|

# 三、完成情况

## 3.1项目推进情况

对于上述七个目标，我们分别是完成了以下几方面的工作：

​&emsp;&emsp;1、确定选题，进行题目分析。讨论方案，搭建开发环境。（已完成）

​&emsp;&emsp;2、对实现内核bypass机制，进行构思，确定bpftime+inode管理功能这个方案。（已完成）

​&emsp;&emsp;3、进行架构设计，对整个方案进行说明，出初稿。（已完成）

​&emsp;&emsp;4、对方案问题进行集体论讨，提出问题，进行解决。（已完成）

​&emsp;&emsp;5、实现bpftime在用户态模式下截断系统调用。(已完成)

​&emsp;&emsp;6、实现inode管理，并且对inode进行优化（利用哈希表、红黑树算法来优化查找）。（已完成）

​&emsp;&emsp;7、fuse文件系统调用inode管理的接口。（已完成）

​&emsp;&emsp;8、在终端对fuse文件系统的用户注册函数进行测试。比如，mkdir、touch、echo、cat、ls。（已完成）

​&emsp;&emsp;9、开辟内存池存储文件数据块内容。（已完成）

​&emsp;&emsp;10、对文件系统性能进行检测，并且完成可视化。（已完成）

​&emsp;&emsp;11、ebpf程序与fuse文件系统之间的通信。（已完成）

​&emsp;&emsp;12、bt-fuse文件系统性能瓶颈分析与未来优化方向。（已完成）


# 四、方案设计

&emsp;&emsp;通过分析赛题，我们制订了一个切实可行的工作路线，首先我们通过bpftime工具对FUSE的系统调用进行拦截，对于符合条件的系统调用引导调用我们自己开发的模块，不再进行系统调用，以此大大减少用户态与内核态的切换次数，提高反应速度。其次我们对于inode进行了重写，将inode单独分装成为一个模块，方便管理并大大提高了其效率。

## 4.1 FUSE架构优化

&emsp;&emsp;利用bpftime工具来优化FUSE的执行过程，当FUSE进行系统调用时，bpftime进行拦截，以减少系统调用的次数。对于系统调用的拦截，我们首先要拿到它的系统调用的参数信息，根据libfuse给出的接口，我们获取到这些参数信息，通过共享内存发送到fuse文件系统，再调用fuse文件系统里面的回调函数。
                        
![](/assets/fig_23.png)

​&emsp;&emsp;关于这个流程：（我们分析有如下优点）

&emsp;&emsp;ebpf截断系统调用会减少用户-内核的模式切换。因为每个FUSE文件操作都需要陷入内核到VFS层，判断是FUSE文件系统类型后再返回用户态。这期间会进行用户-内核的切换，切换过程中可能会进行进程调度。减少该切换会有以下几个好处：

​&emsp;&emsp;1、提高CPU效率：每次进行用户态到内核态的切换时，都需要保存当前进程的状态，并加载内核态的上下文，这个过程涉及到大量的CPU周期。通过减少模式切换的次数，可以使CPU有更多的时间执行实际的应用程序代码，从而提高整体的CPU效率和性能。

​&emsp;&emsp;2、降低系统开销：模式切换需要消耗系统资源，包括但不限于CPU时间、内存带宽等。每次切换都会导致缓存的失效，进而需要重新填充缓存，这会增加内存带宽的压力。减少切换次数能够降低这些开销，使系统资源得到更有效的利用。

​&emsp;&emsp; 原FUSE中，由于会陷入内核，导致可能会进行进程调度，所以原FUSE中会讲一个文件操作记录在一个操作请求结构中，并在用户态操作完成后，将响应结构返回内核，内核会再次解析响应结构，将结果最终返回到用户态的文件操作。这个过程中又会进行一次用户-内核切换，并且在上一个问题的基础上增加了封装请求和响应的问题。bt-fuse因为都是在一个用户态执行流中进行，所以操作流程是一个线性的，不会有异步的问题，进而不需要将文件操作封装为请求-响应的形式。并且用户感知不到bt-fuse文件系统的变化。

​&emsp;&emsp;对于整体原有fuse的执行流的改变，我们借助bpftime的可以截断系统这个功能，将大部分功能全部集成在用户态。如下所示为我们改变fuse执行流后的框架图。

![](/assets/fig_21.png)

​&emsp;&emsp;如图所示：红色的线代表的是bt-fuse文件系统的设计框架流程，黑色的线代表的是原有fuse文件系统的设计框架流程。

​&emsp;&emsp;关于这个框架：（我们分析有如下优点）

​&emsp;&emsp; 我们在用户态做元数据管理的必要性：由于bt-fuse中bypass了内核态的执行，所以无法直接使用内核中的inode管理，bt-fuse中因为需要将每个文件的状态记录起来，所以需要自行维护元数据。

​&emsp;&emsp;缓存问题：假设用户态需要访问的地址已经经过页表映射，即用户态访问的虚拟地址已经映射了对应的物理地址，并且硬件cache上也已经缓存了物理地址中保存的数据。当上述关系建立起来之后，在已映射地址空间中出现cache未命中的情况之前，使用用户空间的虚拟地址访问不会出现缺页异常或者刷新cache的问题。

​&emsp;&emsp;FUSE的作用是提供了一个框架，可以让用户在用户态实现文件操作，FUSE的最终功能函数一定是在用户态的，若最终希望访问到磁盘空间，需要在最终的功能函数中调用接口，这个是FUSE无法解决的。但是这个过程中FUSE可以对操作进行额外的处理，如执行额外的安全和隐私功能，参考AOSP文档（https://source.android.com/docs/core/storage/fuse-passthrough?hl=zh-cn），bt-fuse的作用是尽可能减少从操作请求（如open）到最终操作功能函数（fuse_open）的路径长度。

​&emsp;&emsp;共享内存也是解决了ebpf程序与fuse文件系统之间的及时通信问题。

## 4.2 ebpf截断系统调用

 &emsp;&emsp;1、kprobe截断系统调用
 
 &emsp;&emsp;这里ebpf截断系统调用，除了bpftime可以在用户态截断以外，我们刚开始还尝试了使用kprobe拦截系统调用，但是使用这种方式拦截系统调用是有弊端的，因为是在内核态操作拦截系统调用，会有安全性问题，它的实现目前是主要针对于x86架构，并且需要在内核打开对应的开关才可以使用，我们首次尝试拦截，出于安全考虑，放弃了用这种方式拦截系统调用。

![](/assets/fig_15.jpg)

&emsp;&emsp;如图所示，这是我们使用kprobe拦截系统调用的示例图，我们这里是举例子只拦截了这个ls命令触发的系统调用，根据结果观察，拦截成功。

&emsp;&emsp;2、bpftime截断系统调用

&emsp;&emsp;bpftime截断系统调用是在用户态，所以并不会对内核产生影响从而引发很严重的安全问题。但是我们经过对bpftime的深入研究，发现bpftime与fuse文件系统的结合，仍存在一些问题。

&emsp;&emsp;最为重要的是，我们主要实现的思路是利用截断系统调用，目的是想优化fuse文件系统的性能，但是bpftime在拦截系统调用的时候，它每执行一次系统调用都需要在用户态加载一次它自己实现的一个客户端的动态链接库。经过我们多次测试，根据测试结果分析，它会有很大的性能开销，并且不可避免。

&emsp;&emsp;所以bt-fuse使用bpftime截断系统调用，虽然可行，但是仍然也存在一些问题，但是这个方向，包括bt-fuse这个框架的提出，都是在之前对fuse文件系统的性能优化上面，一个新的方案设计。不可行也是因为目前bpftime对用户来说是一个黑盒，我们没有办法去深入它的低层，去分析以及解决这一问题。

&emsp;&emsp;新的思路的提出

&emsp;&emsp;我们未来是打算可以使用LD_PRELOAD来预加载自定义的动态链接库，并通过它来拦截和重定向系统调用。这样，可以在用户空间拦截系统调用，将请求转发到共享内存，从而提高性能。摒弃掉使用bpftime。或者未来bpftime可以解决它这个在用户态拦截系统调用的时候，加载动态链接库的时候，它的性能问题可以被得到有效的解决。


 ## 4.3 inode管理模块与fuse结合

 ![](/assets/fig_24.png){:width="1000px" height="800px"}

 &emsp;&emsp;inode设计主要围绕上图这几个数据结构所示，将inode的整体数据结构进行重新设计与优化，令其拥有更加高效的运行结构。将inode代码从原FUSE文件管理系统代码中全部抽离进行重构，将inode代码单独管理，实现单一职责原则，使得FUSE文件系统的整体代码耦合度更低，结构更加的合理。实现对inode的九大操作：创建inode、删除inode、读取inode、更改所有者、更改权限与查找inode。

​​&emsp;&emsp;我们将根据Fuse每个回调函数的需求，设计inode功能。分为四部分：

​​&emsp;&emsp;第一部分：Fuse是一个用户空间文件框架，通过回调函数来实现文件系统的各种操作。要将自定义的inode管理部分整合到Fuse文件系统中，通常使用Fuse提供的库函数来创建Fuse文件系统对象。这个对象将包含你的自定义回调函数以及其他必要的信息。根据我们自定义的inode管理部分的功能，实现对应的Fuse回调函数。例如，如果inode管理部分包含创建和删除inode的功能，我们需要实现mkdir、rmdir、unlink、create等回调函数。因为在Fuse文件系统中，一个命令的触发，一般会触发多个回调函数。这是在考虑测试文件系统的时候，一个命令会不会被触发，是牵扯到多个回调函数的。

​​&emsp;&emsp;第二部分：在创建Fuse文件系统对象时，将我们实现的回调函数注册到相应的回调函数指针中。这样当Fuse文件系统接收到对应的操作时，就会调用对应的回调函数来处理。下图为各回调函数执行过程的时序图。

 ![](/assets/fig_27.png)

​​&emsp;&emsp;第三部分：设计inode管理功能，fuse文件系统回调函数调用inode提供的接口，完成相关功能。inode优化主要是采用哈希表、红黑树算法进行查找。

​​&emsp;&emsp;第四部分：开辟内存池存储数据块，inode指针指向数据块。

 ## 4.4 ebpf程序与fuse文件系统的通信

​​&emsp;&emsp;ebpf程序使用环形缓冲区写入共享内存，并且采取分段存储的策略，如下图是ebpf程序的放入数据到共享内存的执行流：

 ![](/assets/fig_25.png)

​​&emsp;&emsp;如下图所示是fuse文件系统从共享内存中取数据的执行流：

 ![](/assets/fig_18.png){:width="500px" height="500px"}

​​&emsp;&emsp;最初在设计ebpf程序与fuse文件系统通信的时候，bt-fuse文件系统选择过netlink、socket等机制，但是最后会选择共享内存作为通信机制的主要原因是它在性能和开销方面相较于socket和netlink机制具有显著优势。共享内存能够减少上下文切换，提升数据传输速度，降低系统调用开销，并且在高并发处理和同步方面表现出色。此外，使用共享内存还能够简化设计和实现过程，并在延迟低场景中提供更好的性能。这些因素使得共享内存成为优化FUSE文件系统性能的理想选择。而socket、netlink机制需要系统调用来发送和接收消息，这些系统调用你会带来额外的开销。

​​&emsp;&emsp; 通过使用共享内存作为 eBPF 程序与 FUSE 文件系统的通信机制，可以实现高效、低延迟的数据传输。共享内存结合环形缓冲区能够有效管理数据读写，提高系统的灵活性和性能。利用futex实现高效的同步机制，利用线程机制避免主线程阻塞，提高系统的响应性。

​​&emsp;&emsp; 使用共享内存的优点：

​​&emsp;&emsp; 1、高效的通信机制:

​​&emsp;&emsp;共享内存允许进程直接访问同一块内存区域，从而避免了数据在进程间拷贝的开销。这使得通信非常快速和高效，特别适用于需要频繁交换大量数据的场景。

​​&emsp;&emsp; 2、低延迟:

​​&emsp;&emsp; 由于共享内存不需要通过内核来进行数据传递，因此减少了系统调用和上下文切换带来的延迟。这对于实时性要求较高的应用场景非常重要。

​​&emsp;&emsp; 3、简单的同步机制:

​​&emsp;&emsp; 使用共享内存时，可以结合信号量、互斥锁等简单的同步原语来确保数据的一致性和并发安全，而不必依赖复杂的内核同步机制。

​​&emsp;&emsp; 使用共享内存缓冲区的优点：

​​&emsp;&emsp; 1、数据传输的灵活性：

​​&emsp;&emsp; 共享内存可以配置为环形缓冲区，允许生产者（eBPF 程序）和消费者（FUSE 文件系统）高效地进行数据读写操作。环形缓冲区能够有效避免频繁的内存分配和释放，减少内存碎片。
​
​&emsp;&emsp; 2、缓冲区管理的高效性:
​​
&emsp;&emsp; 环形缓冲区结构简单，容易实现和管理，可以显著降低系统的复杂性和开销。

&emsp;&emsp; Futex（Fast Userspace Mutex） 

&emsp;&emsp; futex是一种轻量级的用户态锁机制，用于协调多线程访问访问共享内存。在bt-fuse文件系统中，futex用于线程间的同步操作，确保当共享内存中的数据可用时，处理线程能及时被唤醒。

&emsp;&emsp; 优点：

&emsp;&emsp; ●效率高：futex通过在用户态和内核态的结合操作来减少不必要的系统调用开销，只有在需要时才会被触发内核态操作。

&emsp;&emsp; ●轻量级：相比于传统的锁机制，futex在无需进入内核态的情况下能提供快速的同步操作。

&emsp;&emsp; POSIX 线程（pthread）

&emsp;&emsp; bt-fuse文件系统使用了pthread_create创建了一个data_polling_thread,用于异步处理共享内存中的数据。使得文件系统中的主线程不会因为等待数据而阻塞。

&emsp;&emsp; 线程的优点：

&emsp;&emsp; 并发处理：通过多线程机制，可以让文件系统并发地处理多个任务，提高整体性能。

&emsp;&emsp; 响应性：使用单独的线程来处理数据，不会阻塞主线程，保证系统的响应性。

&emsp;&emsp; 利用共享内存、futex 和 pthread 线程机制，在用户态高效地接收并处理 FUSE 文件系统的请求。这种设计实现了低延迟的并发处理，对于需要快速处理大量数据的应用场景非常合适。

&emsp;&emsp;对此之前提出使用io_uring来优化bt-fuse文件系统从共享内存提取数据的过程。（这一方案在进一步优化中被否定，因为io_uring 主要用于处理高并发、大量 I/O 操作的场景。而bt-fuse文件系统的场景中，eBPF 程序写入数据后，FUSE 文件系统立即获取并处理数据的实时性需求更适合使用一种更轻量的同步机制，而非 I/O 操作队列。因此这一方案后续进一步优化的时候被否定了）

# 五、项目测试

## 5.1 测试方法

&emsp;&emsp;为了全面评估本项目对于FUSE文件管理系统的优化效果，我们设计了一套测试框架，以此对我们的文件系统进行全方面的评估。

## 5.2 find命令测试

![](/assets/fig_12.PNG){:width="600px" height="500px"}

&emsp;&emsp; 由测试结果可以看出来，我们的性能比原有fuse文件系统在优化查找方面是大于原有fuse文件系统的。

## 5.3 传统fuse和bt-fuse对比，cat 多少万次一个文件，统计运行时间

![](/assets/fig_11.PNG){:width="600px" height="500px"}

&emsp;&emsp; 由测试结果可以看出来，bt-fuse比原有fuse文件系统性能更好。

# 六、项目开发文档

[决赛第二阶段项目开发文档](https://gitlab.eduxiji.net/T202411664992610/project2210132-232832/-/blob/main/bt-fuse%E6%96%87%E4%BB%B6%E7%B3%BB%E7%BB%9F%E9%A1%B9%E7%9B%AE%E6%8A%A5%E5%91%8A%E5%86%B3%E8%B5%9B%E7%AC%AC%E4%BA%8C%E9%98%B6%E6%AE%B5%E6%B1%87%E6%8A%A5.pdf)

# 七、目录索引

├── README.md   &emsp;&emsp;&emsp;&emsp;##项目简介   
├── bpftime     &emsp;&emsp; ##bpftime的应用代码   
│   ├── error_inject_syacall.bpf.c   &emsp;&emsp; ##截断系统调用程序代码   
│   ├── error_inject_syacall.c    &emsp;&emsp; ##加载用户态ebpf程序代码   
│   └── include   &emsp;&emsp;##头文件   
│       ├── bpf    
│       │   ├── bpf_core_read.h     
│       │   ├── bpf_helper_defs.h     
│       │   ├── bpf_helpers.h       
│       │   └── bpf_tracing.h     
│       ├── error_inject_syacall.h   &emsp;&emsp;##ebpf程序头文件   
│       └── vmlinux      
│           ├── arm64   
│           │   ├── vmlinux.h   
│           │   ├── vmlinux_516.h   
│           │   └── vmlinux_601.h   
│           ├── loongarch   
│           │   ├── vmlinux.h   
│           │   └── vmlinux_602.h     
│           ├── powerpc   
│           │   ├── vmlinux.h   
│           │   └── vmlinux_600.h     
│           ├── riscv   
│           │   ├── vmlinux.h   
│           │   └── vmlinux_602.h   
│           ├── vmlinux.h   
│           └── x86   
│               ├── vmlinux.h     
│               └── vmlinux_601.h   
├── bt_fuse设计开发文档_初赛_.pdf &emsp;&emsp;##初赛开发文档   
├── src   &emsp;&emsp;&emsp;&emsp;&emsp;##代码源目录   
│   ├── fuse_example.c   &emsp;&emsp;##fuse文件系统代码   
│   ├── inode        &emsp;&emsp;##inode管理   
│   │   ├── inode.c    
│   │   └── inode.h    
│   ├── memory     &emsp;&emsp;##memory内存池开辟   
│   │   ├── memory.c     
│   │   └── memory.h    
│   └── shared_memory.c    &emsp;&emsp;##共享内存建立   
├── test    &emsp;&emsp;##测试bt-fuse文件系统性能代码    
│   ├── test_cat_io_fuse.sh    &emsp;&emsp;##测试cat多少万次   
│   └── test_find_fuse.sh    &emsp;&emsp;##测试find指令的查找时间   



