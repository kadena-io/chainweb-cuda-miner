# Configurable variables
LDFLAGS := -lrt -lpthread

CXXFLAGS := -fPIC -std=c++11 -Wall -I. -O6 -march=native -mtune=native -pthread

# We assume nvcc is on the $PATH; you can override this with make NVCC=...
NVCC := nvcc
NVCCFLAGS := -O6 -std=c++11 -Xcompiler=-Wall -Icuda -I. -Xcompiler -fPIC

all: bin/blake2s-gpu-miner bin/blake2s-cpu-miner

clean:
	rm -f *.o
	rm -rf bin

blake2s-cuda.o: blake2s-cuda.cu

bin/blake2s-gpu-miner: blake2s-cuda.o kadena-mine.o
	mkdir -p bin
	$(NVCC) $(NVCCFLAGS) -lrt -lpthread blake2s-cuda.o kadena-mine.o -o bin/blake2s-gpu-miner

bin/blake2s-cpu-miner: blake2s-cpu-miner.o kadena-mine.o
	mkdir -p bin
	$(CXX) $(CXXFLAGS) $(LDFLAGS) blake2s-cpu-miner.o kadena-mine.o -o bin/blake2s-cpu-miner

kadena-mine.cpp: kadena-mine.hpp

%.o: %.cu
	$(NVCC) $(NVCCFLAGS) -c $< -o $@


%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c 	$< -o $@

