#! /bin/bash

option=$1
brightness=$(cat /sys/class/backlight/radeon_bl0/brightness)

if [ $option = '+' ]
then
   let brightness=$brightness+5;
else
   let brightness=$brightness-5;
fi

#while [ true ]
#do
  # read -nl val
   #if [ $val = '+' ]
  # then
    #  let brightness=$brightness+1;
   #else
  #    let brightness=$brightness-1;
 #  fi
#   echo $brightness
#   echo $brightness > /sys/class/backlight/radeon_bl0/brightness
#done

echo $brightness
echo $brightness > /sys/class/backlight/radeon_bl0/brightness
