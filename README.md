DPDKcap

This project consist of a tool that creates pcaps by using multi cores.

setup instructions can be found here:
* https://doc.dpdk.org/guides/

for running dpdkcap parameters look at (skip installation- wrong):
* https://github.com/dpdkcap/dpdkcap

short instructions:

1. clone repo to the server.
2. change hugepages to 1G and OS cores in GRUB.
3. 2 options to compile:
    
	3.1. move to examples/dpdkcap and run make
    
	3.2. use meson as explained in dpdk docs
4. go to the destination directory
5. run "sudo <reposetory path>/examples/dpdkcap/build/dpdkcap  -a "<PCI of coming traffic>"  -l <cores to use> --log-level=8 -- --limit_file_size=500000000 --per_port_c_cores <num1> --num_w_cores <num2> -m <num3> -d <num4> --statistics"
6. for production remove "--log-level=8" and "--statistics"
7. There are 4 numbers that one can be controlled and the function is not convex!
Improving by changing one parameter doesn't mean it is optimal for the function.
Also the running time is critical.
For example, in one configuration there will be a steady drop from the beginning and in another configuration there will be no drop in the beginning and then it will drop all traffic. 

* num1 - number of cores that gets traffic
* num2 - number of cores that creates pcaps
* num3 - number of queues
* num4 - queue size


