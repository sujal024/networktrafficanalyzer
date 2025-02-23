## Network Traffic Analyzer

## Overview

This is a terminal-based real-time network traffic analyzer that captures and displays TCP and UDP packet statistics using libpcap and ncurses. The tool allows users to select a network interface, monitor traffic, and visualize packet trends over time.

## Features

Captures and counts TCP and UDP packets.
Displays real-time network bandwidth usage (KB/s).
Graphically represents traffic trends over the last 25 samples.
Filters available network interfaces and displays only commonly used ones.
Gracefully exits using Ctrl+C.

## Dependencies
Ensure the following libraries are installed before compilation:
sudo apt update
sudo apt install libpcap-dev libncurses5-dev g++

## Selecting an Interface
Once executed, the program lists available network interfaces. Enter the number corresponding to your preferred interface.
Display Information
TCP Packets: Number of TCP packets captured.
UDP Packets: Number of UDP packets captured.
Bandwidth Usage: Current bandwidth usage in KB/s.
Graph: A real-time visualization of TCP (#) and UDP (*) traffic over the last 25 samples.

## Exiting the Program
Press Ctrl+C or Ctrl+Z to stop monitoring and exit cleanly
