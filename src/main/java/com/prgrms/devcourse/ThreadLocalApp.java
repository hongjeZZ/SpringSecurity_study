package com.prgrms.devcourse;

import static java.util.concurrent.CompletableFuture.runAsync;

import java.util.concurrent.CompletableFuture;

public class ThreadLocalApp {

    final static ThreadLocal<Integer> threadLocalValue = new ThreadLocal<>();

    /*
    Spring MVC 는 Thread per Request 모델을 기반으로 만들어졌고,
    Thread per Request 모델에서는 클라이언트 요청을 처리하기 위해서 Thread Pool 을 사용한다.
    결론적으로 Spring MVC 는 ThreadLocal 변수를 사용하고 있고,
    ThreadLocal 을 사용할 때는 클라이언트 요청을 모두 완료한 후에 변수를 반드시 clear() 시켜줘야 한다.
    */

    public static void main(String[] args) {
        System.out.println(getCurrentThreadName() + " ### main set value = 1");
        threadLocalValue.set(1);

        a();
        b();

        /*
        runAsync 안에 묶인 람다 블럭은 main Thread 가 아닌 다른 Thread 에서 실행된다.
        아래 결과를 보면 알다시피 ThreadLocal 변수는 같은 Thread 내에서는 접근할 수 있지만, 다른 Thread 에서는 접근 불가능하다.
        */
        CompletableFuture<Void> task = runAsync(() -> {
            a(); // ForkJoinPool.commonPool-worker-1 ### a() get value = null
            b(); // ForkJoinPool.commonPool-worker-1 ### b() get  value = null
        });
        task.join();
    }

    public static void a() {
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### a() get value = " + value);
    }

    public static void b() {
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### b() get value = " + value);
    }

    public static String getCurrentThreadName() {
        return Thread.currentThread().getName();
    }
}
