#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023-2026 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import argparse
import copy
import logging
import pathlib
import shlex
import subprocess
import tempfile
import typing

import tomlkit


def run(*args, cwd = pathlib.Path.cwd()):
    # Make all paths absolute so that they work regardless of which directory
    # we're running from.
    args = list(args)
    for i, arg in enumerate(args):
        if isinstance(arg, pathlib.Path):
            # Don't make absolute for the command if it's not a path.
            if i > 0 or arg.name != str(arg):
                args[i] = arg.absolute()

    cwd = cwd.absolute()

    logging.info(f'Running: {' '.join(shlex.quote(str(arg)) for arg in args)} [cwd: {cwd}]')

    subprocess.check_call(args, cwd=cwd)


def generate_dynamic_partitions_info(header: tomlkit.TOMLDocument) -> str:
    '''
    Generate the subset of `dynamic_partitions_info.txt` information that can
    be obtained from the header of `payload.bin`. This is all that is needed for
    delta_generator.
    '''

    lines = []

    if d := header['manifest']['dynamic_partition_metadata']:
        lines.append(f'super_partition_groups={' '.join(g['name'] for g in d['groups'])}\n')

        for group in d['groups']:
            if 'size' in group:
                lines.append(f'super_{group['name']}_group_size={group['size']}\n')
                lines.append(f'super_{group['name']}_partition_list={' '.join(group['partition_names'])}\n')

            if d.get('vabc_enabled'):
                lines.append('virtual_ab=true\n')

            if method := d.get('vabc_compression_param'):
                lines.append('virtual_ab_compression=true\n')
                lines.append(f'virtual_ab_compression_method={method}\n')

    return ''.join(lines)


def generate_postinstall_config(header: tomlkit.TOMLDocument) -> str:
    '''
    Generate `postinstall_config.txt` information from the header of
    `payload.bin`.
    '''

    lines = []

    for partition in header['manifest']['partitions']:
        name = partition['partition_name']

        for key in [
            'run_postinstall',
            'postinstall_path',
            'filesystem_type',
            'postinstall_optional',
        ]:
            value = partition.get(key)

            if isinstance(value, bool):
                value = str(value).lower()

            lines.append(f'{key.upper()}_{name}={value}\n')

    return ''.join(lines)


def generate_delta_payload(
    output: pathlib.Path,
    new_header: tomlkit.TOMLDocument,
    old_images: pathlib.Path,
    new_images: pathlib.Path,
    apex_info: pathlib.Path,
    dynamic_partitions_info: pathlib.Path,
    postinstall_config: pathlib.Path,
    delta_generator: pathlib.Path,
):
    '''
    Generate an unsigned delta payload from two directories of complete
    partition images.
    '''

    partition_names = [p['partition_name'] for p in new_header['manifest']['partitions']]
    old_partitions = [str(old_images / (n + '.img')) for n in partition_names]
    new_partitions = [str(new_images / (n + '.img')) for n in partition_names]
    max_timestamp = new_header['manifest'].get('max_timestamp')
    timestamps = [
        f'{p['partition_name']}:{p['version']}'
        for p in new_header['manifest']['partitions']
        if 'version' in p
    ]
    security_patch_level = new_header['manifest'].get('security_patch_level')

    cmd = [
        delta_generator,
        f'--out_file={output}',
        f'--partition_names={':'.join(partition_names)}',
        f'--old_partitions={':'.join(old_partitions)}',
        f'--new_partitions={':'.join(new_partitions)}',
        '--enable_zucchini=true',
        '--enable_lz4diff=false',
        '--enable_vabc_xor=true',
        '--major_version=2',
        '--minor_version=8',
        f'--partition_timestamps={','.join(timestamps)}',
        f'--apex_info_file={apex_info}',
        f'--dynamic_partition_info_file={dynamic_partitions_info}',
        f'--new_postinstall_config_file={postinstall_config}',
    ]

    if max_timestamp is not None:
        cmd.append(f'--max_timestamp={max_timestamp}')

    if security_patch_level is not None:
        cmd.append(f'--security_patch_level={security_patch_level}')

    run(*cmd)


def apply_delta_payload(
    input: pathlib.Path,
    header: tomlkit.TOMLDocument,
    old_images: pathlib.Path,
    new_images: pathlib.Path,
    delta_generator: pathlib.Path,
):
    '''
    Apply a delta payload reading from the old images directory and writing to
    the new images directory.
    '''

    partition_names = [p['partition_name'] for p in header['manifest']['partitions']]
    old_partitions = [str(old_images / (n + '.img')) for n in partition_names]
    new_partitions = [str(new_images / (n + '.img')) for n in partition_names]

    run(
        delta_generator,
        f'--in_file={input}',
        f'--partition_names={':'.join(partition_names)}',
        f'--old_partitions={':'.join(old_partitions)}',
        f'--new_partitions={':'.join(new_partitions)}',
    )


def generate_subcommand(cli):
    def avbroot(*args, **kwargs):
        run(cli.avbroot, *args, **kwargs)

    with tempfile.TemporaryDirectory() as inc_temp_dir:
        inc_temp_dir = pathlib.Path(inc_temp_dir)

        inc_ota_files = inc_temp_dir / 'ota_files'

        with (
            tempfile.TemporaryDirectory() as old_temp_dir,
            tempfile.TemporaryDirectory() as new_temp_dir,
        ):
            old_temp_dir = pathlib.Path(old_temp_dir)
            new_temp_dir = pathlib.Path(new_temp_dir)

            logging.info('Unpacking both full OTAs')
            avbroot(
                'zip', 'unpack', '-q',
                '-i', cli.input_old,
                '--payload',
                cwd=old_temp_dir,
            )
            avbroot(
                'zip', 'unpack', '-q',
                '-i', cli.input_new,
                '--payload',
                cwd=new_temp_dir,
            )

            logging.info('Loading OTA metadata from old OTA')
            with open(old_temp_dir / 'ota.toml', 'r') as f:
                old_ota = tomlkit.load(f)

            logging.info('Loading OTA metadata from new OTA')
            with open(new_temp_dir / 'ota.toml', 'r') as f:
                new_ota = tomlkit.load(f)

            logging.info('Loading payload metadata from new OTA')
            with open(new_temp_dir / 'payload.toml', 'r') as f:
                new_payload = tomlkit.load(f)

            dynamic_partitions_info = inc_temp_dir / 'dynamic_partitions_info.txt'
            postinstall_config = inc_temp_dir / 'postinstall_config.txt'
            unsigned_payload = inc_temp_dir / 'payload.bin'

            logging.info('Moving extra files from new OTA')
            (new_temp_dir / 'ota_files').move(inc_ota_files)

            logging.info('Creating partial dynamic_partitions_info.txt')
            with open(dynamic_partitions_info, 'w') as f:
                f.write(generate_dynamic_partitions_info(new_payload))

            logging.info('Creating postinstall_config.txt')
            with open(postinstall_config, 'w') as f:
                f.write(generate_postinstall_config(new_payload))

            logging.info('Generating unsigned incremental payload.bin')
            generate_delta_payload(
                unsigned_payload,
                new_payload,
                old_temp_dir / 'payload_images',
                new_temp_dir / 'payload_images',
                inc_ota_files / 'apex_info.pb',
                dynamic_partitions_info,
                postinstall_config,
                cli.delta_generator,
            )

        # We don't need the source images anymore.

        logging.info('Signing incremental payload.bin')
        avbroot(
            'payload', 'repack', '-q',
            '-i', unsigned_payload,
            '-o', inc_ota_files / 'payload.bin',
            '--output-properties', inc_ota_files / 'payload_properties.txt',
            *avbroot_sign_args(cli),
        )

        logging.info('Creating incremental OTA zip')

        # Set up preconditions checks to ensure that the incremental OTA can
        # only be applied on top of the correct source OS build.
        inc_ota = copy.deepcopy(new_ota)
        inc_precondition = inc_ota['metadata']['precondition']
        old_postcondition = old_ota['metadata']['postcondition']

        for key in ('build', 'build_incremental'):
            inc_precondition[key] = old_postcondition[key]

        with open(inc_temp_dir / 'ota.toml', 'w') as f:
            tomlkit.dump(inc_ota, f)

        avbroot(
            'zip', 'pack', '-q',
            '-o', cli.output_inc,
            *avbroot_sign_args(cli, cert=True),
            cwd=inc_temp_dir,
        )


def apply_subcommand(cli):
    def avbroot(*args, **kwargs):
        run(cli.avbroot, *args, **kwargs)

    with tempfile.TemporaryDirectory() as new_temp_dir:
        new_temp_dir = pathlib.Path(new_temp_dir)

        new_ota_files = new_temp_dir / 'ota_files'
        new_ota_files.mkdir()

        new_images = new_temp_dir / 'payload_images'
        new_images.mkdir()

        with (
            tempfile.TemporaryDirectory() as old_temp_dir,
            tempfile.TemporaryDirectory() as inc_temp_dir,
        ):
            old_temp_dir = pathlib.Path(old_temp_dir)
            inc_temp_dir = pathlib.Path(inc_temp_dir)

            logging.info('Unpacking full OTA')
            avbroot(
                'zip', 'unpack', '-q',
                '-i', cli.input_old,
                '--payload',
                cwd=old_temp_dir,
            )

            logging.info('Unpacking incremental OTA')
            avbroot(
                'zip', 'unpack', '-q',
                '-i', cli.input_inc,
                cwd=inc_temp_dir,
            )

            inc_payload_file = inc_temp_dir / 'ota_files' / 'payload.bin'

            logging.info('Creating skeleton partition images')
            avbroot(
                'payload', 'unpack', '-q',
                '-i', inc_payload_file,
                '--output-images', new_images,
                '--skeleton',
                cwd=inc_temp_dir,
            )

            logging.info('Loading OTA metadata from full OTA')
            with open(old_temp_dir / 'ota.toml', 'r') as f:
                old_ota = tomlkit.load(f)

            logging.info('Loading OTA metadata from incremental OTA')
            with open(inc_temp_dir / 'ota.toml', 'r') as f:
                inc_ota = tomlkit.load(f)

            logging.info('Loading payload metadata from incremental OTA')
            with open(inc_temp_dir / 'payload.toml', 'r') as f:
                inc_payload = tomlkit.load(f)

            logging.info('Moving extra files from incremental OTA')
            for p in (inc_temp_dir / 'ota_files').iterdir():
                if p.name != 'payload.bin' and p.name != 'payload_properties.txt':
                    p.move_into(new_ota_files)

            logging.info('Applying incremental payload.bin')
            apply_delta_payload(
                inc_payload_file,
                inc_payload,
                old_temp_dir / 'payload_images',
                new_images,
                cli.delta_generator,
            )

        # We don't need the source images anymore.

        logging.info('Creating full OTA zip')

        # Use the new metadata, but with the old full OTA's preconditions, which
        # won't make any assertions about the currently installed OS.
        new_ota = copy.deepcopy(inc_ota)
        new_ota['metadata']['precondition'] = old_ota['metadata']['precondition']

        with open(new_temp_dir / 'ota.toml', 'w') as f:
            tomlkit.dump(new_ota, f)

        # No need for a newer minor version for full OTAs.
        new_payload = copy.deepcopy(inc_payload)
        new_payload['manifest']['minor_version'] = 0

        with open(new_temp_dir / 'payload.toml', 'w') as f:
            tomlkit.dump(new_payload, f)

        avbroot(
            'zip', 'pack', '-q',
            '-o', cli.output_new,
            '--payload',
            *avbroot_sign_args(cli, cert=True),
            cwd=new_temp_dir,
        )


def avbroot_sign_args(args, cert: bool = False) -> list(str | pathlib.Path):
    cmd = ['--key', args.key]

    if cert:
        cmd.append('--cert')
        cmd.append(args.cert)

    if args.pass_env_var:
        cmd.append('--pass-env-var')
        cmd.append(args.pass_env_var)

    if args.pass_file:
        cmd.append('--pass-file')
        cmd.append(args.pass_file)

    if args.signing_helper:
        cmd.append('--signing-helper')
        cmd.append(args.signing_helper)

    return cmd


def parse_args():
    parser = argparse.ArgumentParser()

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument(
        '--avbroot',
        default='avbroot',
        type=pathlib.Path,
        help='Path to avbroot executable',
    )
    base.add_argument(
        '--delta-generator',
        default='delta_generator',
        type=pathlib.Path,
        help='Path to delta_generator executable',
    )

    # These signing arguments are directly passed to avbroot.
    base.add_argument(
        '--key',
        required=True,
        type=pathlib.Path,
        help='Private key for signing the OTA',
    )
    base.add_argument(
        '--cert',
        required=True,
        type=pathlib.Path,
        help='Certificate for OTA signing key',
    )
    base.add_argument(
        '--pass-env-var',
        help='Environment variable containing the private key passphrase',
    )
    base.add_argument(
        '--pass-file',
        help='Text file containing the private key passphrase',
    )
    base.add_argument(
        '--signing-helper',
        help='External program for signing',
    )

    subparsers = parser.add_subparsers(required=True, dest='subcommand')

    generate = subparsers.add_parser(
        'generate',
        help='Generate an incremental OTA from two full OTAs',
        parents=[base],
    )
    generate.add_argument(
        '--input-old',
        required=True,
        help='Path to old full OTA zip file',
    )
    generate.add_argument(
        '--input-new',
        required=True,
        help='Path to new full OTA zip file',
    )
    generate.add_argument(
        '--output-inc',
        required=True,
        help='Path to output incremental OTA zip file',
    )

    apply = subparsers.add_parser(
        'apply',
        help='Generate a full OTA from a full OTA and an incremental OTA',
        parents=[base],
    )
    apply.add_argument(
        '--input-old',
        required=True,
        help='Path to old full OTA zip file',
    )
    apply.add_argument(
        '--input-inc',
        required=True,
        help='Path to incremental OTA zip file',
    )
    apply.add_argument(
        '--output-new',
        required=True,
        help='Path to output full OTA zip file',
    )

    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='\x1b[1m[%(levelname)s] %(message)s\x1b[0m',
    )

    match args.subcommand:
        case 'generate':
            generate_subcommand(args)

        case 'apply':
            apply_subcommand(args)

        case subcommand:
            typing.assert_never(subcommand)


if __name__ == '__main__':
    main()
