# SPDX-License-Identifier: LGPL-2.1+

project('rederr', 'c',
        version : '1',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu99',
        ]
)

add_project_arguments(
        ['-Wextra',
        '-Werror=undef',
        '-Wlogical-op',
        '-Wmissing-include-dirs',
        '-Wold-style-definition',
        '-Wpointer-arith',
        '-Winit-self',
        '-Wfloat-equal',
        '-Wsuggest-attribute=noreturn',
        '-Werror=missing-prototypes',
        '-Werror=implicit-function-declaration',
        '-Werror=missing-declarations',
        '-Werror=return-type',
        '-Werror=incompatible-pointer-types',
        '-Werror=format=2',
        '-Wstrict-prototypes',
        '-Wredundant-decls',
        '-Wmissing-noreturn',
        '-Wimplicit-fallthrough=5',
        '-Wshadow',
        '-Wendif-labels',
        '-Wstrict-aliasing=2',
        '-Wwrite-strings',
        '-Werror=overflow',
        '-Werror=shift-count-overflow',
        '-Werror=shift-overflow=2',
        '-Wdate-time',
        '-Wnested-externs',
        '-Wno-unused-parameter',
        '-Wno-missing-field-initializers',
        '-Wno-unused-result',
        '-Wno-format-signedness'],
        language : 'c')

exe = executable(
        'rederr',
        ['rederr.c'],
        install: true
)
