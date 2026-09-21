LLVM_CONFIG ?= llvm-config-14
CXX = clang++-14
CXXFLAGS ?= -std=c++17 -O2 -pthread

LLVM_INCLUDE := $(shell $(LLVM_CONFIG) --includedir)
LLVM_FLAGS := $(shell $(LLVM_CONFIG) --cxxflags --ldflags --libs core)
CLANG_LIBS := -lclangTooling -lclangFrontend -lclangDriver -lclangSerialization \
	-lclangParse -lclangSema -lclangAnalysis -lclangAST -lclangBasic \
	-lclangEdit -lclangLex -lclangASTMatchers -lclangRewrite
LOG_FILE := ast-analyzer-compile.log

all: ast_analyzer

ast_analyzer: ast_analyzer.cpp helper.cpp helper.hpp
	$(CXX) ast_analyzer.cpp helper.cpp -o $@ -I$(LLVM_INCLUDE) $(LLVM_FLAGS) $(CLANG_LIBS) $(CXXFLAGS) 2>&1 | tee $(LOG_FILE)

clean:
	rm -f ast_analyzer $(LOG_FILE)

.PHONY: all clean
