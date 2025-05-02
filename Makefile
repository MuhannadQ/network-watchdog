.PHONY: capture train monitor visualize clean all help

# Default target
help:
	@echo "Available targets:"
	@echo "  capture    - Run the packet capture script"
	@echo "  train      - Run the training script"
	@echo "  monitor    - Run the monitoring script"
	@echo "  visualize  - Run the visualization script"
	@echo "  clean      - Clean up generated files"
	@echo "  all        - Run the complete pipeline (capture, train, monitor)"

capture:
	sudo python3 main.py capture --interface en0

train:
	sudo python3 main.py train

monitor:
	sudo python3 main.py monitor --interface en0

# Visualization is still separate as it's not in main.py actions
visualize:
	sudo python3 visualization.py

# Run the complete pipeline
all: capture train monitor

# Clean up generated files
clean:
	rm -f *.pyc
	rm -rf __pycache__