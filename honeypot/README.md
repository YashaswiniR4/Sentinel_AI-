# Honeypot & Cybersecurity Module

## Project

AI-Driven Cloud Threat Intelligence System

## Module

Member 1 – Cybersecurity & Honeypot

## Objective

The objective of this module is to simulate honeypot-based security monitoring and collect structured security activity logs for further analysis by the AI/ML module.

## Components

### 1. HTTP Honeypot

File:
`http/http_honeypot.py`

The HTTP honeypot provides controlled fake endpoints such as:

* `/`
* `/admin`
* `/login`
* `/test`

It records incoming HTTP requests and stores the activity in:

`logs/http_logs.json`

### 2. SSH Honeypot Simulation

File:
`ssh/ssh_honeypot.py`

The SSH component safely simulates suspicious SSH login attempts and command activity in a controlled local environment.

The generated activity is stored in:

`logs/ssh_logs.json`

### 3. Attack/Activity Simulator

File:
`simulator/attack_simulator.py`

The simulator generates controlled test security events for both SSH and HTTP activities.

The generated events are stored in:

`logs/simulator_logs.json`

### 4. Log Converter

File:
`log_converter.py`

The log converter combines the collected JSON logs and converts them into a structured CSV dataset.

Output:

`logs/security_logs.csv`

## Extracted Security Features

The final CSV contains fields including:

* timestamp
* ip
* protocol
* method
* request
* username
* login_success
* command
* event
* failed_attempts
* session_duration
* command_count

These structured features are provided to the AI/ML module for anomaly detection and risk analysis.

## Workflow

HTTP Honeypot ──┐
│
SSH Simulation ─┼──> JSON Logs
│
Activity Simulator ┘
↓
Log Converter
↓
security_logs.csv
↓
AI/ML Module

## Technologies

* Python
* Flask
* JSON
* CSV
* GitHub

## Safety

This module is designed for controlled academic testing. The SSH component is a local simulation and does not expose a real SSH service or collect real credentials.

## Team Integration

The generated `security_logs.csv` will be used by Member 2 for preprocessing, anomaly detection, and risk-score generation.
