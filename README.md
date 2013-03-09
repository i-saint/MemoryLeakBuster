MemoryLeakBuster
================
this code is public domain.  
latest version: https://github.com/i-saint/MemoryLeakBuster  
written by i-saint ( http://primitive-games.jp )  

メモリリーク検出器。  
この .cpp をプロジェクトに含めるだけで有効になり、プログラム終了時にリーク箇所の確保時のコールスタックをデバッグ出力に表示します。  
また、実行中にイミディエイトウィンドウから使える便利機能をいくつか提供します。

*   mlbInspect((void*)address)  
    指定メモリ領域の確保時のコールスタックや近隣領域を出力します。  
    (stack 領域、static 領域の場合それぞれ "stack memory", "static memory" と出力します)

*   mlbBeginScope() & mlbEndScope()  
    mlbBeginScope() を呼んでから mlbEndScope() を呼ぶまでの間に確保され、開放されなかったメモリがあればそれを出力します。

*   mlbBeginCount() & mlbEndCount()  
    mlbBeginCount() を呼んでから mlbEndCount() を呼ぶまでの間に発生したメモリ確保のコールスタックとそこで呼ばれた回数を出力します。
    デバッグというよりもプロファイル用機能です。

*   mlbOutputToFile  
    leak 情報出力をファイル (mlbLog.txt) に切り替えます。  
    デバッグ出力は非常に遅いので、長大なログになる場合ファイルに切り替えたほうがいいでしょう。


設定ファイル (mlbConfig.txt) を書くことで外部から挙動を変えることができます。  
設定ファイルは以下の書式を受け付けます。  

*   disable: 0/1  
    リークチェックを無効化します。

*   fileoutput: 0/1  
    出力先をファイル (mlbLog.txt) にします。

*   module: "hoge.dll"  
    指定モジュールをリークチェックの対象にします。

*   ignore: "!functionname"  
    指定パターンを含むコールスタックのリークを表示しないようにします。


リークチェックの仕組みは CRT の HeapAlloc/Free を hook することによって実現しています。  
CRT を static link したモジュールの場合追加の手順が必要で、下の g_crtdllnames に対象モジュールを追加する必要があります。  

![mlb1](/img/mlb1.png "mlb1")
![mlb2](/img/mlb2.png "mlb2")
![mlb3](/img/mlb3.png "mlb3")
