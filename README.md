# exe_solver
PE EXE solver

ЗАДАЧИ:

1.	Изучить существующие подходы, применяемые для выявления и анализа триггерного поведения во вредоносном программном обеспечении [1-4].
2.	Изучить подходы, применяемые для автоматизации анализа программного обеспечения (символьное выполнение и динамическая бинарная инструментация, taint-анализ, Data-Flow-Analysis) и распространенные средства анализа (angr, Triton, S2E, BAP, miasm, и другие) [5]. 
3.	Разработать программу, которая обеспечивает автоматизированное осуществление следующих операций:
3.1.	 Статический анализ исполняемого файла (crackme/ВПО) и определение в нем целевого кода программы (sink), обеспечение выполнения которого является решением crackme, либо выполнением вредоносных действий программы. Необходимо найти в программе все ветви программы, приводящие к выполнению внешних вызовов (вызовы функций из других библиотек, выполнение системных вызовов, либо прерываний).
3.2.	 Нахождение в исследуемой программе всех мест считывания внешних данных (source) (например, scanf, fscanf, gets, ReadFile, …), от значений которых зависит достижимость внешних вызовов (sink).
3.3.	 Анализ программы и выявление в ней механизмов защиты от анализа (антиотладочные и анти-ВМ механизмы), противодействующие корректному выполнению программы под средствами отладки и инструментации.
3.4.	 Автоматизированный обход выявленных механизмов защиты программы путем модификации исполняемого кода программы (патчинга), динамической инструментации кода, либо перехвата выполнения (hooking).
3.5.	 Используя средства инструментации и динамического символьного выполнения реализовать автоматизированное нахождение входных значений программы (source) для достижения всех целевых мест осуществления вызовов внешних функций (sink).
