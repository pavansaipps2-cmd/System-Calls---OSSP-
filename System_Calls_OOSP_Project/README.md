# System Call Monitoring and Analysis Tool

## Abstract
This project implements a user-space system call monitoring and analysis tool in C on Ubuntu, adhering strictly to course requirements that prohibit modifying the Linux kernel[cite: 1]. The application intercepts, logs, and analyzes kernel invocations using `ptrace`[cite: 1].

## Team Details
* **Section:** 03[cite: 1]
* **Team No:** 16[cite: 1]
* **Members:**
  * P.Pavan Sai (2520030417)[cite: 1]
  * U.Ankith (2520030403)[cite: 1]
  * T.Akilesh (2520030570)[cite: 1]

## How to Compile & Run
```bash
make
./tracer ./target