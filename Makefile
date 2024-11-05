# Colors for pretty output
YELLOW := "\033[1;33m"
GREEN  := "\033[1;32m"
RED    := "\033[1;31m"
BLUE   := "\033[1;34m"
CYAN   := "\033[1;36m"
RESET  := "\033[0m"

# Python package manager - prefer pip3 if available
PIP := $(shell command -v pip3 2> /dev/null || echo pip)

# Python version information
REQUIRED_PYTHON_VERSION := 3.9.7
CURRENT_PYTHON_VERSION := $(shell python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
PYTHON_VERSION_STATUS := /tmp/python_version_status.txt

# Check if running with sudo
SUDO := $(shell id -u)
ifeq ($(SUDO),0)
    SUDO_CMD :=
else
    SUDO_CMD := sudo
endif

# Required external Python packages with specific versions
REQUIREMENTS := requests==2.32.3 colorama==0.4.6 openpyxl==3.1.5 prettytable==3.11.0 tzlocal alive-progress==3.1.5 pytz==2024.2

# Variables to store installation status
SYSTEM_DEPS_STATUS := /tmp/system_deps_status.txt
PYTHON_DEPS_STATUS := /tmp/python_deps_status.txt

# Default target
.PHONY: all
all: check-python-version system-deps install-deps check-csv permissions show-summary
	@echo ${GREEN}"\n=== Setup Complete ==="${RESET}

# Check Python version
.PHONY: check-python-version
check-python-version:
	@echo ${BLUE}"\n=== Checking Python Version ==="${RESET}
	@echo ${YELLOW}"→ Verifying Python version..."${RESET}
	@echo "Current Python Version: $(CURRENT_PYTHON_VERSION)" > $(PYTHON_VERSION_STATUS)
	@echo "Required Python Version: $(REQUIRED_PYTHON_VERSION)" >> $(PYTHON_VERSION_STATUS)
	@if python3 -c "import sys; exit(0) if tuple(map(int, '$(CURRENT_PYTHON_VERSION)'.split('.'))) >= tuple(map(int, '$(REQUIRED_PYTHON_VERSION)'.split('.'))) else exit(1)" 2>/dev/null; then \
		echo ${GREEN}"✓ Python version $(CURRENT_PYTHON_VERSION) meets the minimum requirement ($(REQUIRED_PYTHON_VERSION))"${RESET}; \
		echo "Python Version Check:SUCCESS" >> $(PYTHON_VERSION_STATUS); \
	else \
		echo ${RED}"! Python version $(CURRENT_PYTHON_VERSION) is below the recommended version ($(REQUIRED_PYTHON_VERSION))"${RESET}; \
		echo ${YELLOW}"  This script was written using Python $(REQUIRED_PYTHON_VERSION). Some features might not work as expected."${RESET}; \
		echo "Python Version Check:WARNING" >> $(PYTHON_VERSION_STATUS); \
	fi

# Install system dependencies
.PHONY: system-deps
system-deps:
	@echo ${BLUE}"\n=== Installing System Dependencies ==="${RESET}
	@rm -f $(SYSTEM_DEPS_STATUS)
	@echo ${YELLOW}"→ Updating system package list..."${RESET}
	@if $(SUDO_CMD) apt-get update >/dev/null 2>&1; then \
		echo ${GREEN}"✓ System package list updated successfully"${RESET}; \
		echo "System package update:SUCCESS" >> $(SYSTEM_DEPS_STATUS); \
	else \
		echo ${RED}"✗ Failed to update package list. Are you running with sudo?"${RESET}; \
		echo "System package update:FAILED" >> $(SYSTEM_DEPS_STATUS); \
		exit 1; \
	fi
	
	@echo ${YELLOW}"→ Installing jq-1.6 package..."${RESET}
	@if $(SUDO_CMD) apt-get install -y jq=1.6* >/dev/null 2>&1; then \
		echo ${GREEN}"✓ jq-1.6 installed successfully"${RESET}; \
		echo "jq-1.6 package:SUCCESS" >> $(SYSTEM_DEPS_STATUS); \
	else \
		echo ${RED}"✗ Failed to install jq-1.6"${RESET}; \
		echo "jq-1.6 package:FAILED" >> $(SYSTEM_DEPS_STATUS); \
		exit 1; \
	fi

# Install required Python dependencies
.PHONY: install-deps
install-deps:
	@echo ${BLUE}"\n=== Installing Python Dependencies ==="${RESET}
	@rm -f $(PYTHON_DEPS_STATUS)
	@for package in $(REQUIREMENTS); do \
		echo ${YELLOW}"→ Installing $$package..."${RESET}; \
		if $(PIP) install $$package --upgrade 2>/dev/null; then \
			echo "$$package:SUCCESS" >> $(PYTHON_DEPS_STATUS); \
			echo ${GREEN}"✓ $$package installed successfully"${RESET}; \
		else \
			echo "$$package:FAILED" >> $(PYTHON_DEPS_STATUS); \
			echo ${RED}"✗ Failed to install $$package"${RESET}; \
		fi; \
	done

# Check if csv module is available
.PHONY: check-csv
check-csv:
	@echo ${BLUE}"\n=== Checking CSV Module ==="${RESET}
	@echo ${YELLOW}"→ Verifying csv module availability..."${RESET}
	@if python3 -c "import csv" 2>/dev/null; then \
		echo ${GREEN}"✓ csv module is available (built-in with Python)"${RESET}; \
		echo "csv module:SUCCESS" >> $(PYTHON_DEPS_STATUS); \
	else \
		echo ${RED}"✗ Python csv module not found. Please check your Python installation"${RESET}; \
		echo "csv module:FAILED" >> $(PYTHON_DEPS_STATUS); \
		exit 1; \
	fi

# Set executable permissions
.PHONY: permissions
permissions:
	@echo ${BLUE}"\n=== Setting File Permissions ==="${RESET}
	@echo ${YELLOW}"→ Current permissions for Spectra_Shield.py:"${RESET}
	@ls -l Spectra_Shield.py
	@echo ${YELLOW}"\n→ Setting executable permissions..."${RESET}
	@chmod +x Spectra_Shield.py || \
		(echo ${RED}"Failed to set executable permissions"${RESET} && exit 1)
	@echo ${GREEN}"✓ New permissions for Spectra_Shield.py:"${RESET}
	@ls -l Spectra_Shield.py
	@echo ${CYAN}"  Owner: $(shell stat -c '%U' Spectra_Shield.py)"${RESET}
	@echo ${CYAN}"  Group: $(shell stat -c '%G' Spectra_Shield.py)"${RESET}
	@echo ${CYAN}"  Mode:  $(shell stat -c '%A' Spectra_Shield.py)"${RESET}

# Show installation summary
.PHONY: show-summary
show-summary:
	@echo ${BLUE}"\n=== Installation Summary ==="${RESET}
	@echo ${YELLOW}"Python Version Information:"${RESET}
	@if [ -f $(PYTHON_VERSION_STATUS) ]; then \
		while IFS=':' read -r line; do \
			if [ "$$(echo "$$line" | grep -c "Version Check")" -gt 0 ]; then \
				status=$$(echo "$$line" | cut -d':' -f2 | tr -d ' '); \
				if [ "$$status" = "SUCCESS" ]; then \
					echo ${GREEN}"✓ Python version is compatible"${RESET}; \
				else \
					echo ${YELLOW}"! Python version needs attention"${RESET}; \
				fi; \
			else \
				echo ${CYAN}"  $$line"${RESET}; \
			fi; \
		done < $(PYTHON_VERSION_STATUS); \
	fi

	@echo ${YELLOW}"\nSystem Dependencies:"${RESET}
	@if [ -f $(SYSTEM_DEPS_STATUS) ]; then \
		while IFS=':' read -r line; do \
			pkg=$$(echo "$$line" | cut -d':' -f1); \
			status=$$(echo "$$line" | cut -d':' -f2 | tr -d ' '); \
			if [ "$$status" = "SUCCESS" ]; then \
				echo ${GREEN}"✓ $$pkg"${RESET}; \
			else \
				echo ${RED}"✗ $$pkg"${RESET}; \
			fi; \
		done < $(SYSTEM_DEPS_STATUS); \
	fi
	
	@echo ${YELLOW}"\nPython Dependencies:"${RESET}
	@if [ -f $(PYTHON_DEPS_STATUS) ]; then \
		while IFS=':' read -r line; do \
			pkg=$$(echo "$$line" | cut -d':' -f1); \
			status=$$(echo "$$line" | cut -d':' -f2 | tr -d ' '); \
			if [ "$$status" = "SUCCESS" ]; then \
				echo ${GREEN}"✓ $$pkg"${RESET}; \
			else \
				echo ${RED}"✗ $$pkg"${RESET}; \
			fi; \
		done < $(PYTHON_DEPS_STATUS); \
	fi
	
	@echo ${YELLOW}"\nFile Permissions:"${RESET}
	@echo ${GREEN}"✓ Spectra_Shield.py is now executable"${RESET}
	
	@rm -f $(SYSTEM_DEPS_STATUS) $(PYTHON_DEPS_STATUS) $(PYTHON_VERSION_STATUS)

# Clean up any generated files or caches
.PHONY: clean
clean:
	@echo ${BLUE}"\n=== Cleaning Up ==="${RESET}
	@find . -type d -name "__pycache__" -exec rm -r {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@rm -f $(SYSTEM_DEPS_STATUS) $(PYTHON_DEPS_STATUS) $(PYTHON_VERSION_STATUS)
	@echo ${GREEN}"✓ Cleanup completed"${RESET}

# Help target
.PHONY: help
help:
	@echo ${BLUE}"=== Available Targets ==="${RESET}
	@echo "  all          - Set up everything (default)"
	@echo "  system-deps  - Install system dependencies (requires sudo)"
	@echo "  install-deps - Install Python dependencies"
	@echo "  permissions  - Set executable permissions"
	@echo "  clean        - Remove generated files"
	@echo "  help         - Show this help message"
