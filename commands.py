
from contextlib import contextmanager
from functools import cache
import logging as log
# from os import PathLike
from pathlib import Path
import time
from typing import Iterable, Optional

from invoke.context import Context
from invoke.runners import Result


class Bash:
    """
    Runs a bash command on a remote server using pyinvoke Context.
    > sh = Bash(ctx, command1)
    > sh.run_as(user, password)
    > sh(command2).run()
    """
    flag_exists = {"file": "-f", "dir": "-d"}

    def __init__(self, c: Context, cmd: str=""):
        self.c = c
        self.cmd = cmd
        self.hide_ = True
        self.warn_ = False

    def __call__(self, cmd: str) -> "Bash":
        "Sets a command to run"
        self.cmd = cmd
        return self

    @property
    def show(self) -> "Bash":
        "Print output"
        self.hide_ = False
        return self

    @property
    def hide(self) -> "Bash":
        "Hide output"
        self.hide_ = True
        return self

    @property
    def warn(self) -> "Bash":
        "Warn if command fails (no exception)"
        self.warn_ = True
        return self

    @property
    def fail(self) -> "Bash":
        "Raise exception if command fails"
        self.warn_ = False
        return self

    def run(self, user: "str|None"=None, password: "str|None"=None, enc='utf-8') -> Result:
        """
        Run command in bash, optionally as a specified user.

        https://github.com/pyinvoke/invocations/blob/6331c0e242b6bd10a88b191ada3bd486d5b67ecd/invocations/travis.py#L73
        https://github.com/fabric/fabric/issues/1862 How to change directory in v2.3
        """
        c = self.c
        cmd = self.cmd
        cwds = c.command_cwds
        prefixes = c.command_prefixes
        c.command_cwds = []
        c.command_prefixes = []
        if prefixes or cwds:
            cmd = " && ".join([f"cd {i}" for i in cwds] + prefixes + [cmd])
        cmd = cmd.replace("'", r"'\''")  # https://unix.stackexchange.com/questions/30903 escape '
        try:
            if user and user != self.c.user:
                # Инициализируем окружение пользователя с помощью ~/.bash_profile
                # см. https://superuser.com/questions/671372/running-command-in-new-bash-shell-with-rcfile-and-c
                # В интерактивном режиме (-i) можно указать --rcfile ~/.bash_profile,
                # но при этом в консоль выводится приветствие (если есть)
                # Поэтому выполняем ~/.bash_profile вручную https://stackoverflow.com/a/29571113
                cmd = f"bash -c 'source ~{user}/.bash_profile; {cmd}'"
                # Echoing a password is a security risk! https://stackoverflow.com/q/233217#comment42036267_4327123
                # e.g. result = c.run(f"echo '{password}\n' | su - {user} -c {cmd} 2>/dev/null", hide=self.hide_, warn=self.warn_)
                kwargs = {}
                if password:
                    # to use default `config.sudo.password` don't pass password argument to `sudo`
                    kwargs["password"] = password
                result = c.sudo(cmd, user=user, **kwargs, hide=self.hide_, warn=self.warn_, encoding=enc)
            else:
                cmd = f"bash -c '{cmd}'"
                result = c.run(cmd, hide=self.hide_, warn=self.warn_, encoding=enc)
        finally:
            c.command_prefixes = prefixes
            c.command_cwds = cwds
        return result

    def realpath(self, path: str, type=None) -> "Bash":
        """
        Преобразует существующий путь на удалённом сервере в абсолютный.
        Раскрывает переменные: ~, $HOME, и т.д.
        Если путь не найден, возвращает None

        Arguments:
        `type` - тип пути: file, dir, или None (по умолчанию любой)
        """
        # return c.run(f'cd {path} && pwd', hide=True).stdout.strip()
        # realpath: https://stackoverflow.com/a/14892459
        # realpath -e проверяет существование пути, иначе не возвращает ошибку,
        # если последний компонент пути не найден
        # https://linuxize.com/post/bash-check-if-file-exists
        # `echo "echo {path}" | bash` https://stackoverflow.com/a/66181138
        cmd = f'realpath -qe `echo "echo {path}" | bash`'
        if type:  # проверяем тип пути: file или dir
            exists = self.flag_exists[type.lower()]
            cmd = f'P=$({cmd}) && [ {exists} $P ] && echo $P'
        return self(cmd)


class Packages:
    MSG_DO_INSTALL = "Выполнить установку"

    def __init__(self, c: Context):
        self.c = c

    def install(self, packages: "Iterable[str]|str"):
        """
        Install system packages.
        `packages` - can be a list of packages or an absolute path to a
                     folder with packages
        """
        pkg_path: Optional[str] = None  # Path to a folder with packages
        if isinstance(packages, str):
            pkg_path = realpath(self.c, packages, type='dir')
            if not pkg_path:
                raise ValueError(f"Invalid package source folder: {packages}")
            packages = [Path(i).stem for i in ls(self.c, Path(pkg_path) / '*.rpm')]

        if self.is_installed(packages, with_version=bool(pkg_path)):
            log.warning("All packages are already installed")
            return
                
        cmd_pkg_install = 'yum install '
        if pkg_path:  # https://serverfault.com/q/940791
            cmd_pkg_install += f'{pkg_path}/*'
        else:
            cmd_pkg_install += " ".join(packages)
        res = self.c.run(f'{cmd_pkg_install} --assumeno', warn=True)
        if res.failed and input(f"{self.MSG_DO_INSTALL} [y/N]? ") == "y":
            res = self.c.run(f'{cmd_pkg_install} -y', warn=True)

        if not self.is_installed(packages, with_version=bool(pkg_path)):
            log.error("Packages were NOT installed")
            raise EnvironmentError("Packages were NOT installed")

    def is_installed(self, packages: Iterable[str], with_version: bool=False,
                     verbose=False) -> bool:
        "Проверяет, установлены ли все указанные пакеты"
        # Get the list of installed package names
        # В каждой строке списка пакетов выбираем текст до первой точки:
        # > yum list installed | awk -F. '{print $1}'
        # yum может переносить строки, для скриптов лучше RPM: https://bugzilla.redhat.com/show_bug.cgi?id=584525#c1
        cmd = R'rpm -qa'  # package names with version
        if not with_version:  # package names only
            cmd += R' --qf "%{name}\n"'
        result = self.c.run(cmd, warn=True, hide=True)
        if result.failed:
            return False
        installed = result.stdout.splitlines()
        # Check if all packages are installed
        ret = True
        for i in packages:
            if not i in installed:
                ret = False
                if verbose:
                    log.warning(f"Package {i} is not installed")
            else:
                if verbose:
                    log.info(f"Package {i} is installed")
        return ret


class User:
    "Проверка существования пользователя, создание"
    def __init__(self, c: Context, username: str, password: str=""):
        self.c = c
        self.name = username
        self.password = password
    
    @property
    @cache
    def home(self) -> Optional[str]:
        "Абсолютный путь к директории пользователя или None"
        return realpath(self.c, f"~{self.name}")

    def exists(self):
        "Проверяет, существует ли пользователь"
        result = self.c.run('id -u {}'.format(self.name), warn=True, hide=True)
        return result.ok

    def create(self, home: Optional[str]=None):
        """
        Создаёт пользователя user (см. settings.json) на сервере.
        Домашний каталог может быть задан в параметре home или выбран по умолчанию.
        """
        command = f'useradd {self.name}'
        if home:  # /home/lv_kps/kpsuser
            self.c.run(f"mkdir -p {Path(home).parent.as_posix()}")
            command += f' --home-dir {home}'
        self.c.run(command)
    
    def __str__(self):
        return self.name


class FileTools:
    def __init__(self, c: Context, user: "User|None"):
        self.c = c
        self.user = user.name if user else None
        self.passw = user.password if user else ""

    def mkdir(self, path: str):
        """
        Создаёт дерево папок на сервере и возвращает абсолютный путь.
        При невозможности создать папку возникает исключение UnexpectedExit
        """
        Bash(self.c, f'mkdir -p {path}').run(self.user, self.passw)
        result = Bash(self.c).realpath(path).warn.run(self.user, self.passw)
        if result.ok:
            return result.stdout.strip()

    def upload(self, files: Iterable[str], local_folder: Path, rem_folder: str):
        """
        Загружает файлы на удалённый сервер.
        Перечень файлов задаётся в секции `upload` файла settings.json:
            * root_local - корневая директория с файлами на локальном компьютере
            * root_remote - директория для загрузки на удалённом сервере
            * секции с файлами и директориями для загрузки на сервер
        На вход принимает список секций из settings.json/upload или 'all'
        """
        remote_folder = realpath(self.c, rem_folder, self.user, self.passw, type='dir')
        if not remote_folder:
            raise EnvironmentError(f"Remote folder not found {rem_folder}")
        remote_filelist = self.fetch_remote_filelist(remote_folder, relative=True)

        for rel_path in files:
            abs_path = Path(local_folder) / rel_path
            # Получение абсолютных путей к файлам на локальной машине
            local_filelist = self.list_local_paths(abs_path) if abs_path.is_dir() \
                             else [abs_path]
            for file in local_filelist:
                rel_p = file.relative_to(local_folder)
                if rel_p.as_posix() not in remote_filelist:
                    upload_dir = (remote_folder/rel_p).parent.as_posix()
                    print(f"{rel_p} > {upload_dir}...")
                    self.c.run(f'mkdir -p {upload_dir}')
                    self.c.put(file, upload_dir)
                else:
                    print(f"{rel_p} exists")

    def fetch_remote_filelist(self, path: str, relative=False):
        """
        Возвращает список файлов на удалённом сервере

        :param path: путь к каталогу на удалённом сервере
        :param relative: возвращать пути относительно указанного каталога
        """
        # https://stackoverflow.com/a/10574806
        command = f'find {path} -type f'
        if relative:
            # https://unix.stackexchange.com/a/104805
            command += r" -printf '%P\n'"
        return Bash(self.c, command).warn.run(self.user, self.passw).stdout.splitlines()

    def list_local_paths(self, path: Path):
        """
        Возвращает список путей к файлам из локальной директории

        :param path: путь к локальной директории
        """
        return [Path(p) for p in path.glob('**/*') if p.is_file()]

    def unpack(self, filepath: str, path: str):
        """
        Распаковывает архив tar.gz в указанную директорию
        """
        with self.c.cd(path):
            Bash(self.c, f'tar -xzf {filepath}').run(self.user, self.passw)

    def rm(self, path: str):
        """
        Удаляет файл или директорию на удалённом сервере.
        При невозможности удаления ошибка игнорируется.
        """
        Bash(self.c, f'rm -rf {path}').warn.run(self.user, self.passw)

    @contextmanager
    def context_unpack(self, filepath: str, path: str):
        """
        Распаковывает архив tar.gz, при выходе из контекста файлы удаляются
        """
        self.unpack(filepath, path)
        yield
        print(f'Removing unpacked files from {path}/{tar_basename(filepath)}')
        self.rm(f'{path}/{tar_basename(filepath)}')

    @contextmanager
    def context_exists(self, paths: "str|Iterable[str]"):
        result = {}
        paths = (paths,) if isinstance(paths, str) else tuple(paths)
        result['test'] = all(
            realpath(self.c, fp, self.user, self.passw) for fp in paths
        )
        yield result
        result['test'] = all(
            realpath(self.c, fp, self.user, self.passw) for fp in paths
        )
        if not result['test']:
            if len(paths) == 1:
                log.error(f'{paths[0]} path not found!')
            else:
                log.error(f'Any of {paths} paths not found!')


class Build:
    def __init__(self, c: Context, path: str, user: "User|None"):
        self.c = c
        self.user = user.name if user else None
        self.passw = user.password if user else ""
        self.path = path

    def configure(self, arguments: str="", test_strings: "Iterable|None"=None) -> Result:
        """
        Конфигурирует проект для сборки.
        `arguments` - аргументы для команды `configure`
        `test_strings` - список строк для проверки вывода конфигурации
        """
        log.info(f"Configuring {self.path}...")
        with self.c.cd(self.path):
            res = Bash(self.c, './configure ' + arguments).show.run(self.user, self.passw)
            for i in test_strings or []:
                if i not in res.stdout:
                    raise EnvironmentError(f"Configure failed: '{i}' not found in output")
            return res

    def build(self, arguments: str="") -> Result:
        """
        Производит сборку проекта
        """
        log.info(f"Building {self.path}...")
        with self.c.cd(self.path):
            return Bash(self.c, 'make ' + arguments).show.run(self.user, self.passw)

    def install(self, alt: bool=False) -> Result:
        """
        Производит установку собранного приложения
        """
        log.info(f"Install from {self.path}...")
        with self.c.cd(self.path):
            s_alt = 'alt' if alt else ''
            return Bash(self.c, f'make {s_alt}install').show.run(self.user, self.passw)


@contextmanager
def context_port(c: Context, port: int, timeout: int):
    """
    Context command to test if a specified TCP port was opened.
    Raises exception if port is already busy on __enter__.
    """
    cmd_port_check = f"ss -tln | grep :{port}"
    # 0 - line selected, 1 - no lines selected, 2 - error
    res = c.run(cmd_port_check, hide=True, warn=True).return_code == 0
    if res:
        log.warn(f"Port {port} is already busy!")
    result = {'test': res}
    yield result
    start_time = cur_time = time.perf_counter()
    msg_printed = False
    while cur_time - start_time < timeout:
        res = c.run(cmd_port_check, hide=True, warn=True).return_code == 0
        if res:
            break
        elif not msg_printed:
            log.warn(f"Waiting for port {port} to become busy for {timeout} seconds...")
            msg_printed = True
        time.sleep(1)
        cur_time = time.perf_counter()
    result['test'] = res


def ls(c: Context, path: Path):
    # -1 flag needed?
    return c.run(f"ls {path.as_posix()}", hide=True).stdout.splitlines()


def realpath(c: Context, path: str, user: "str|None"=None, password: str="",
             type=None) -> Optional[str]:
    "Преобразование к абсолютному пути и проверка, см. Bash.realpath"
    result = Bash(c).realpath(path, type).warn.run(user, password)
    if result.ok:
        return result.stdout.strip()

def tar_basename(path: str) -> str:
    "Возвращает имя архива из пути без расширения"
    suffixes = ['.tar', '.tar.gz', '.tar.bz2', '.tar.xz', '.tgz', '.tbz2', '.txz']
    p = Path(path)
    for suffix in suffixes:
        if p.name.lower().endswith(suffix):
            return p.name[:-len(suffix)]
    raise ValueError(f'{path} is not a tar file')


class Firewall:
    "Firewalld management"
    def __init__(self, c: Context):
        self.c = c

    def allow_tcp_port(self, port: int):
        "Allow access to TCP port in firewalld"
        self.c.run(
            f"firewall-cmd --permanent --zone=public --add-port={port}/tcp && firewall-cmd --reload"
        )
