A Try to move from trivy_runner to a pipeline based workflow

Calling the pipeline:

```
vpereira@linux-qouy:~/catalog_scanner_pipeline> dagger call scan-pipeline --base-dir "/tmp" --image-gun "alpine:latest" --base-url http://localhost:8080/foo -v
✔ connect 0.8s
✔ initialize 0.9s
✔ CatalogScannerPipeline.scanPipeline(baseDir: "/tmp", baseUrl: "http://localhost:8080/foo", imageGun: "alpine:latest"): String! 1.3s
  ✔ Container.from(address: "registry.opensuse.org/home/vpereirabr/dockerimages/containers/vpereirabr/airflow_runner:latest"): Container! 0.1s
  ✔ Container.stdout: String! 0.4s
    ✔ exec curl -X POST -H Content-Type: application/json -d @/tmp/alpine_latest.json http://localhost:8080/foo?image=alpine:latest 0.4s
    ┃   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current                                                   
    ┃                                  Dload  Upload   Total   Spent    Left  Speed                                                     
    ┃ 100  1637  100    27  100  1610    269  16055 --:--:-- --:--:-- --:--:-- 16370                                                    
    ┃ Request received and logged                                                                                                       

Request received and logged
```

And on the server we've got a payload like:

```
Body: {  "SchemaVersion": 2,  "CreatedAt": "2024-05-28T12:00:18.84329037Z",  "ArtifactName": "/tmp/alpine_latest.tar",  "ArtifactType": "container_image",  "Metadata": {    "OS": {      "Family": "alpine",      "Name": "3.20.0"    },    "ImageID": "sha256:1d34ffeaf190be23d3de5a8de0a436676b758f48f835c3a2d4768b798c15a7f1",    "DiffIDs": [      "sha256:02f2bcb26af5ea6d185dcf509dc795746d907ae10c53918b6944ac85447a0c72"    ],    "ImageConfig": {      "architecture": "amd64",      "container": "0f7ab8998cdbfb81d62c7749d84ca590a41a159db683d8452cfc9ca4f2b68261",      "created": "2024-05-22T18:18:12.052034407Z",      "docker_version": "20.10.23",      "history": [        {          "created": "2024-05-22T18:18:11.872913732Z",          "created_by": "/bin/sh -c #(nop) ADD file:e3abcdba177145039cfef1ad882f9f81a612a24c9f044b19f713b95454d2e3f6 in / "        },        {          "created": "2024-05-22T18:18:12.052034407Z",          "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",          "empty_layer": true        }      ],      "os": "linux",      "rootfs": {        "type": "layers",        "diff_ids": [          "sha256:02f2bcb26af5ea6d185dcf509dc795746d907ae10c53918b6944ac85447a0c72"        ]      },      "config": {        "Cmd": [          "/bin/sh"        ],        "Env": [          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"        ],        "Image": "sha256:7d045e0d1e17c4a19585d99b4e80d8691a6b90ae5cdf5d99610c7db1e3565732"      }    }  },  "Results": [    {      "Target": "/tmp/alpine_latest.tar (alpine 3.20.0)",      "Class": "os-pkgs",      "Type": "alpine"    }  ]}
```
