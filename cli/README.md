# Tempesta Escudo Client Management Tool

## Running

```
$ ./BUILD/tfw --help
Usage:
  tfw <command> [command options] [global options]

Commands:
  push      send data to server (--conf <file>, --conf-inline <config>, --patch <file>, --patch-inline <patch>, --tl <program>)
  reload    reload server config and geolocation DB

Global options:
  -h [ --help ]                    show this message and exit
  -d [ --debug ]                   run in debugging mode
  -s [ --server ] arg (=127.0.0.1) server address to connect to
  -p [ --port ] arg (=50051)       server port
```

## Unit testing

```
$ make test # from root dir
```



