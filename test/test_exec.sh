#!/bin/bash
set -e

echo "Устанавливаем модуль..."
sudo insmod /home/sofiia/Desktop/acos/acos_morozovasophiia/uid_exec.ko

echo "Разрешим юзеру 666 для наглядности"
echo "666" | sudo tee /proc/exec_allow

echo "Запускаем ls - должно сработать для юзера 666:"
ls

echo "Запускаем ls для другого юзера - должно заблочить:"
sudo -u nobody ls || echo "Заблокирован(((."

echo "Удаляем модуль..."
sudo rmmod uid_exec
