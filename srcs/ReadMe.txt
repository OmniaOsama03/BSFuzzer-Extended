1.修改from Semantic.srcs.Config_File.Microchip import config 为要测试设备的config，例如TI 等
2.nohup /home/yangting/miniconda3/envs/python3.11/bin/python /home/yangting/Documents/Semantic/srcs/ble_fuzzing.py >> /home/yangting/Documents/Semantic/result/log_file/Microchip/test.log
3.output:在相应设备的/home/yangting/Documents/Semantic/result/log_file/Microchip/semfuzz_output.json
4.运行信息在：/home/yangting/Documents/Semantic/result/log_file/Microchip/test.log，如果test.log出现了connect error先插拔小usb
5.插拔后对fuzz 函数或者fuzz connect 函数的log 值 改为semfuzz output的最后的log值