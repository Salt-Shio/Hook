這個專案用於實驗和研究在 linux 下 hook 的運作

主要透過 Gemini 輔助實作

當前的目標: 
1. 啟動一個暫停執行的 elf
2. hook 某個位址
3. 讓目標 elf 把記憶體或是暫存器的內容塞進某個檔案，藉此紀錄某些過程

當前的進度: jmp 到 .text 區段上寫更長的 jmp 到 inject_lib，最後在把原本蓋掉的 5 bytes 執行，並回到 main 繼續
缺點: 太多地方要手工了，之後考慮加入 capstone 自動分析

希望可以應用在針對 VM 的逆向，把 opcode 的順序丟到檔案
