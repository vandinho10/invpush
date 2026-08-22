CXX      ?= g++
STD      := -std=c++17
WARN     := -Wall -Wextra -Wpedantic
OPTFLAGS := -O2
DBGFLAGS := -O0 -g

VERSION  := 1.0.0
TARGET   := invpush
TESTBIN  := tests/test_runner
TESTBIN_SAN := tests/test_runner_san

# Alvo do sistema: alvo nativo por padrao; passe TARGET_OS=Windows_NT ao
# compilar com mingw-w64 (x86_64-w64-mingw32-g++ / i686-w64-mingw32-g++).
TARGET_OS ?= $(shell uname -s)

# Windows (MinGW): binario 100% estatico com transporte WinHTTP nativo.
# POSIX: transporte libcurl dinamico (libcurl4-openssl-dev).
ifeq ($(TARGET_OS),Windows_NT)
  LIBS := -static -static-libgcc -static-libstdc++ -lwinhttp -liphlpapi -lws2_32
else
  LIBS := -lcurl
endif

CXXFLAGS := $(STD) $(WARN)

SRCS := main.cpp invpush.cpp

.PHONY: all check test sanitize version install clean

all: $(TARGET)

$(TARGET): $(SRCS) invpush.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) -DINVPUSH_VERSION=\"$(VERSION)\" -o $@ $(SRCS) $(LIBS)

# Verificacao estatica: warnings tratados como erro
check:
	$(CXX) $(CXXFLAGS) -Werror -fsyntax-only $(SRCS)
	@echo "verificacao ok (zero warnings)"

$(TESTBIN): tests/invpush_tests.cpp invpush.cpp invpush.hpp tests/test_framework.hpp
	$(CXX) $(CXXFLAGS) $(DBGFLAGS) -I. -DINVPUSH_VERSION=\"$(VERSION)\" -o $@ tests/invpush_tests.cpp invpush.cpp $(LIBS)

test: $(TESTBIN)
	./$(TESTBIN)

# Build com sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer)
$(TESTBIN_SAN): tests/invpush_tests.cpp invpush.cpp invpush.hpp tests/test_framework.hpp
	$(CXX) $(CXXFLAGS) $(DBGFLAGS) -I. -fsanitize=address,undefined -fno-omit-frame-pointer -DINVPUSH_VERSION=\"$(VERSION)\" -o $@ tests/invpush_tests.cpp invpush.cpp $(LIBS)

sanitize: $(TESTBIN_SAN)
	./$(TESTBIN_SAN)

version:
	@echo "$(TARGET) v$(VERSION)"

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/bin/invpush

clean:
	rm -f $(TARGET) $(TARGET).exe $(TESTBIN) $(TESTBIN_SAN)
