# Project Title
IPBlockOptimizer

## Description
IPBlockOptimizer optimizes the allocation of IP blocks to Autonomous Systems using the Gale-Shapley algorithm. This tool is designed to enhance network performance and security by ensuring stable and efficient IP block distribution.

 consider the case where a RIR has a list of AS's which are looking for new IP allocations, 
 and a list of IP address blocks which are ready to be allocated. Is it possible to allocate these
 in a way where you optimize network performance / security while not giving bias towards any
 of the AS's?

## Installation
```bash
git clone https://github.com/kazkianoush/IPBlockOptimizer.git
cd IPBlockOptimizer
python IPAllocToSMP.py
