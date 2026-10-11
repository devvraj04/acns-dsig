#!/bin/bash
# Envelope and Payload Fuzz Testing Script
set -e

echo "Running ACNS-DSIG fuzz testing against envelope parser..."
# Tests corrupted base64, truncated payloads, and random bitflips
./mvnw test "-Dtest=EnvelopeFuzzTest" "-Dsurefire.failIfNoSpecifiedTests=false"
