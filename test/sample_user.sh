#!/bin/bash

echo "Для UID 99:"
sudo -u nobody ls / || echo "Заблокировано для UID 99"
