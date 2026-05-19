## Done:
* Capabilities narrowing
* Interface for interacting with scanner
## In test:
* Syscall recorder
* Profile generator
* AppArmor scanner
## Backlog:
* benchmarks
* security tests
* Thesis paperwork
* Tech loan



## Plan for benchmarks and security tests:
#### security tests:

тесты при уже полученном RCE в докер. покажу, что генерированные конфиги смогли бы исключить эскейп или другие действия на хосте или других контейнерах.

думаю сделать несколько тестов, один по CVE-2019-5736, и пару на мисконфигурации (широкие капабилити или маунты)

#### benchmarks 

хочу попробовать эту тулзу https://github.com/lnsp/touchstone, если не выйдет, то можно сравнить как сравнивали crun с runc 
https://github.com/containers/crun
```
crun is faster than runc and has a much lower memory footprint.

This is the elapsed time on my machine for running sequentially 100 containers, the containers run /bin/true:
```

