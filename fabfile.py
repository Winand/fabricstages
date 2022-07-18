import json
import logging as log
from contextlib import ExitStack
from pathlib import Path
from typing import Optional

from fabric import task
from invoke.context import Context

from commands import (Bash, Build, FileTools, Packages, User, context_port,
                      realpath)

log.basicConfig(level="INFO", format='%(levelname)s: %(message)s')

@task
def install_ssh_key(c):
    """
    Добавляет публичный ключ пользователя на удалённый сервер для доступа по SSH
    """
    # https://github.com/paramiko/paramiko/blob/609e01d550f62253c56c34fc5a49d01f1d49e6e2/paramiko/client.py#L714
    local_pubkey = None
    for keytype in ("rsa", "dsa", "ecdsa", "ed25519"):
        key_file = Path.home() / f".ssh/id_{keytype}.pub"
        if key_file.exists():
            local_pubkey = key_file
            break
    if not local_pubkey:
        raise FileNotFoundError(f"Не найден ключ пользователя в {Path.home() / '.ssh'}")
    key_content = Path(local_pubkey).read_text()
    if key_content in c.run("cat ~/.ssh/authorized_keys", hide=True, warn=True).stdout:
        log.warning("Ключ уже установлен на сервере")
    else:
        c.run("mkdir -p -m 700 ~/.ssh")
        # Создание файла с правами 600 https://stackoverflow.com/a/21343912
        # umask указывает какие биты НЕ будут установлены при создании файла
        c.run(f'umask 077 && echo "{key_content}" >> ~/.ssh/authorized_keys')
    # Включение доступа по ключу (не требуется?)
    # c.run(R"sed -i '/PubkeyAuthentication/c\#PubkeyAuthentication yes' /etc/ssh/sshd_config")

@task
def internet(c, switch):
    """
    Включение/отключение интернета на удалённом сервере (подмена шлюза) [on|off]
    """
    # Другой вариант: добавить правила iptables через direct-интерфейс firewalld
    # https://www.reddit.com/r/CentOS/comments/ot9vkb/block_all_internet_access_with_firewalld/h6tw8rb/
    # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/using_the_direct_interface
    # https://access.redhat.com/discussions/3238521
    sw: str = switch.lower()
    if sw in ('on', 'y', 'yes'):
        # Восстановление шлюза по умолчанию
        c.run("ip route del `ip route | grep 199`", warn=True, hide=True)
    elif sw in ('off', 'n', 'no'):
        if input(f"Отключить шлюз по умолчанию на {c.host} [y/N]? ") == "y":
            c.run(
                "ip route add default via `ip route | grep default | awk '{print $3}'`99",
                warn=True, hide=True
            )
    else:
        raise ValueError(f"Unknown switch '{switch}'")


def run_stage(st: dict, c: Context, u: User, is_context: bool = False):
    if st.get("skip"):
        log.info("Skipped " + st.get('name', ''))
        return
    cmd = st["cmd"]
    if 'context' in st and is_context:
        raise ValueError("Нельзя использовать контекст в контексте")  # FIXME: нужно?
    ctx_result = []
    with ExitStack() as stack:
        context = st.get('context', [])
        st_test: "dict|list" = st.get('test', [])
        if isinstance(st_test, dict):
            st_test = [st_test]
        context += st_test
        ctx_result = [stack.enter_context(ctx) for ctx in 
             (run_stage(i, c, u, is_context=True) for i in context)
             if ctx]
        # Check context results for passed tests
        tests = [ctx['test'] for ctx in ctx_result if ctx and 'test' in ctx]
        if tests and all(tests):
            log.info("All tests passed, stage skipped")
            return

        if cmd == 'packages':
            pkg = Packages(c)
            pkg_source = st['packages']
            if isinstance(pkg_source, str):
                pkg_source = realpath(c, pkg_source, user=str(u))
                if not pkg_source:
                    raise EnvironmentError(f"Package source {st['packages']} not found")
            pkg.install(pkg_source)
        elif cmd == 'upload':
            fsh = FileTools(c, user=u)
            fsh.mkdir(st['root_remote'])
            fsh.upload(st['files'], st['root_local'], st['root_remote'])
        elif cmd == 'unpack':
            fsh = FileTools(c, user=u)
            if is_context:
                return fsh.context_unpack(st['file'], st['output'])
            fsh.unpack(st['file'], st['output'])
        elif cmd == 'build':
            b = Build(c, st['source'], u)
            b.configure(st['options'], st.get('test_configure'))
            b.build()
            b_install = st.get('install')
            if b_install:
                b.install(alt=b_install=="alt")
        elif cmd == 'run':
            if is_context:
                return c.prefix(st['command'])
            b = Bash(c, st['command'])
            if st.get('show', True):
                b = b.show
            b.run(u.name, u.password)
        elif cmd == 'exists':
            if is_context:
                return FileTools(c, user=u).context_exists(st['path'])
            raise ValueError("`exists` can be used in context only")
        elif cmd == 'user':
            u = User(c, st['username'])
            pref_home: Optional[str] = st.get('home')
            if u.exists():
                if pref_home and u.home and pref_home != u.home:
                    log.warning(f"User {u} already exists, but home is {u.home} "
                                f"not {pref_home}")
                else:
                    log.warning(f"User {u} already exists")
            else:
                u.create(home=pref_home)
        elif cmd == 'echo':
            output = st.get('output', '')
            if output:
                fsh = FileTools(c, user=u)
                fsh.mkdir(Path(output).parent.as_posix())
                if st.get('append'):
                    output = ">> " + output
                else:
                    output = "> " + output
            # Here document https://linuxize.com/post/bash-heredoc
            Bash(c, f'cat << ~EOF~ {output}\n{st["text"]}\n~EOF~').show.run(u.name, u.password)
        elif cmd == 'port':
            if is_context:
                return context_port(c, int(st['port']), int(st.get('timeout', 30)))
            raise ValueError("`port` can be used in context only")
        else:
            raise ValueError(f"Unknown command {cmd}")

    # Check context results for passed tests
    tests = [ctx['test'] for ctx in ctx_result if ctx and 'test' in ctx]
    if not all(tests):
        raise ValueError(f"`{cmd}` stage failed")


@task(default=True)
def main(c, scenario='scenario.yaml'):
    with open(scenario, encoding="utf-8") as f:
        if scenario.lower().endswith(".yaml"):
            import yaml
            sc = yaml.safe_load(f)
        else:
            sc = json.load(f)
    pref_user = sc['user']
    u = User(c, pref_user['name'])
    for i, st in enumerate(sc['stages']):
        log.info(f"Stage {i+1}/{len(sc['stages'])} ({st.get('cmd', '')}) {st.get('name', '')}")
        run_stage(st, c, u)
