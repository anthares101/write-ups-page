---
description: Write up about the process of creating my personal Kubernetes cluster
---

<style>
  .source {
    border: 1px solid #ddd;
    border-radius: 3px;
    padding: 1.5em;
    word-break: break-all;
  }

  figure {
    margin: 1.25em 0;
    page-break-inside: avoid;
  }

  .icon {
    display: inline-block;
    max-width: 1.2em;
    max-height: 1.2em;
    text-decoration: none;
    vertical-align: text-bottom;
    margin-right: 0.5em;
    margin-top: 0.1em;
  }

  .bookmark {
    text-decoration: none;
    max-height: 8em;
    padding: 0;
    display: flex;
    width: 100%;
    align-items: stretch;
  }

  .bookmark-title {
    font-size: 0.85em;
    overflow: hidden;
    text-overflow: ellipsis;
    height: 1.75em;
    white-space: nowrap;
  }

  .bookmark-text {
    display: flex;
    flex-direction: column;
    text-align: left;
  }

  .bookmark-info {
    flex: 4 1 180px;
    padding: 12px 14px 14px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  .bookmark-image {
    width: 33%;
    flex: 1 1 180px;
    display: block;
    position: relative;
    object-fit: cover;
    border-radius: 1px;
  }

  .bookmark-description {
    font-size: 0.65em;
    overflow: hidden;
    max-height: 4.5em;
    word-break: break-word;
  }

  .bookmark-href {
    font-size: 0.75em;
    margin-top: 0.25em;
    display: flex;
  }
</style>

*20 min read*
# MAGI project

## The idea

I have been thinking about the idea of building a cluster made of Raspberrys and update my home infrastructure a bit. Right now, I use a Raspberry Pi 4 B as a little server to run Pi Hole, personal projects, Plex... and also as a NAS. All this sevices are run using Docker containers because I love Docker and the management is easier that way, allowing me to recover from a failure really quick.

Since I’m increasing the load to it with more things and some application like Plex sometimes consumes A LOT a cluster could be awesome. After thinking a bit my options I discovered PicoCluster:

<figure>
  <a href="https://www.picocluster.com/" class="bookmark source">
    <div class="bookmark-info">
      <div class="bookmark-text">
        <div class="bookmark-title">PicoCluster - Desktop Micro Data Center</div>
        <div class="bookmark-description">Kubernetes Docker Cluster Software Advanced Kits and Assembled Cubes come with 4GB Raspberry 4 boards. Starter Kits support 1GB, 2GB and 4GB boards.</div>
      </div>
      <div class="bookmark-href">
        <img src="https://cdn.shopify.com/s/files/1/1214/6676/files/PicoClusterRobot_1inch_32x32.png?v=1506826884" class="icon bookmark-icon"/>https://www.picocluster.com/
      </div>
    </div><img src="https://cdn.shopify.com/s/files/1/1214/6676/files/PicoClusterLogoFinal_150.png?height=628&amp;pad_color=fff&amp;v=1494390559&amp;width=1200" class="bookmark-image"/>
  </a>
</figure>

They have a lot of cool things and one of them is exactly what I needed, a little cluster with 3 Raspberrys. I bought it, if it is not obvious by now, and the plan is to migrate some of the things I have running in my actual Pi to it.

The idea is simple, my initial Raspberry will only have essential network services like Pi Hole (Working as DHCP and DNS server), Samba (Used for backups and to add things to Plex) and Netdata for monitoring it 24/7 and alert me if something is going wrong. Meanwhile, the cluster will use that Pi for storage provisioning and will host the rest of application like Plex, Nextcloud, personal projects... 

Also, as part of this project I want to make sure I can still recover from a terminal failure without a ton of problems and learn a bit more of Ansible. The idea here is that all the cluster initial installation and setup will be performed by an Ansible Playbook that I will create from scratch.

### What are you going to read

Anthares from the future here! The initial idea sounds great right? A cluster of Raspberrys what a cool thing! Well, looks like migrating all to Kubernetes from a Docker setup is not as straightforward as I thought. Also, while I was working on it I started thinking about improving the security of the new infrastructure and fix some problems I had taking advantage of some Kubernetes features.

What I though It was going to be a fast and smooth process (I already have worked with Kubernetes and Helm before) ended up being a really long journey of reading documentation and unexpected problems BUT I really learnt a lot.

I tried to cover all the process I followed during my journey so I invite you to relax, get a coffee or something and join me in this adventure, Its going to be a long one. Keep in mind that this is not a Kubernetes tutorial, if you want to follow my steps you are supposed to already know a bit about how things works in Kubernetes.

Oh! I almost forgot about it. Keep in mind that the 64 bit version of Raspbian was just released yesterday, 02/04/2022, so obviously during the installation process of this write up I had to install a pre-release version of it.

## Assembly

After waiting a bit (I’m in Spain so it is a long way from the US) a received my order!

![Assembly1.jpg](/assets/images/Projects/MAGI_Project/Assembly1.jpg)

You can ask them to do the assembly process or even install the applications you want into the cluster to avoid wasting time setting it up but... that is not fun right?

The assembly process is documented fairly well in their site and you will only need a screwdriver and some different size heads for it in order to follow all the process.

![Assembly2.jpg](/assets/images/Projects/MAGI_Project/Assembly2.jpg)

By the way, you can ask them to only send the parts for the cluster but not the actual boards for it. The thing is that with the chip shortage we have right now the price they sell them for is just too good to not get all from them.

The assembly took me around 2 hours or so but it was pretty fun to do and it looks incredible:

![Assembly3.jpg](/assets/images/Projects/MAGI_Project/Assembly3.jpg)

## Preparing the SD cards

We have a cool looking cube right now, time to bring it to life! The first thing to do is to prepare the SD cards with Raspbian and a basic headless setup (No monitors please).

In this case I want to use the 64 bit version of Raspbian (Even though it is still under development and have some issues) because since Apple started using ARM a lot of applications work with ARM64 and can be handy. This Raspbian version can be downloaded from here:

<figure><a href="https://downloads.raspberrypi.org/raspios_arm64/images/" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">Index of /raspios_arm64/images</div></div><div class="bookmark-href"><img src="https://downloads.raspberrypi.org/favicon.ico" class="icon bookmark-icon"/>https://downloads.raspberrypi.org/raspios_arm64/images/</div></div></a></figure>

I will use the Raspberry Pi imager program to put Raspbian in the SD cards. You can find this software here:

<figure><a href="https://www.raspberrypi.com/software/" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">Raspberry Pi OS - Raspberry Pi</div><div class="bookmark-description">From industries large and small, to the kitchen table tinkerer, to the classroom coder, we make computing accessible and affordable for everybody.</div></div><div class="bookmark-href"><img src="data:image/png;base64,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" class="icon bookmark-icon"/>https://www.raspberrypi.com/software/</div></div><img src="https://assets.raspberrypi.com/static/opengraph-6d80de9a444335c577028951fd1bab78.png" class="bookmark-image"/></a></figure>

There is an option in the program for custom images that works like a charm:

![imager](/assets/images/Projects/MAGI_Project/imager.png)

It will take a while just to prepare one card so imagine 3 of them.

Once the cards are prepared, we have to do one more thing. Since we don’t want to use a monitor we have to connect the cards to the computer, open the disk called `boot` and create a file called `ssh` . This will enable SSH by default.

The only problem right now is that the IP address for each Raspberry Pi will be provided by the DHCP server so in the first boot you will need to find them in the network.

## Initial setup

My idea is to create an ansible playbook to make all the initial setup of the cluster, that way if a terminal failure happens I can just get everything setup in the blink of an eye.

But as I said above, the Raspberrys will have a random IP in the first boot so I will have to connect to them one by one to setup an static IP address and hostnames. After that, we can add SSH key authentication and from there I can start with the playbook to setup everything.

I know it is not perfect because if something goes wrong and I need to reinstall from a clean SD card, I will need to do this whole process of connecting to the Raspberry and make the very first setup by hand before I can use the playbook but I think it is ok for me.

Note: I had an error with the 64 bit Raspbian OS about the `locale` value. I just executed `sudo dpkg-reconfigure locales` and generated the language that the error was crying about.

## Cluster setup

All the steps described in this section will be included in an Ansible playbook to make this whole process automatic. You can check the playbook here:

<figure><a href="https://github.com/anthares101/k3s-pi-cluster" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">GitHub - anthares101/k3s-pi-cluster: K3S Pi Cluster project playbook</div><div class="bookmark-description">The monitoring stack used is the Carlos Eduardo version of the kube-prometheus repo and part of the Ansible roles were adapted from Jeff Geerling turing-pi-cluster project.</div></div><div class="bookmark-href"><img src="https://github.com/favicon.ico" class="icon bookmark-icon"/>https://github.com/anthares101/k3s-pi-cluster</div></div><img src="https://opengraph.githubassets.com/4075e0b5616e1dcbb8d015fab617a6f5699030f68f60e25994f092bc53ffa304/anthares101/k3s-pi-cluster" class="bookmark-image"/></a></figure>

### Basic Raspberrys setup

Raspbian comes with some stuff configured that we don’t really need, Wi-Fi and Bluetooth for example. To disable them we can just add this to the `/boot/config.txt` file and reboot:

```
dtoverlay=pi3-disable-wifi
dtoverlay=pi3-disable-bt
```

The next thing is to prevent the default `pi` user from using the `sudo` command without a password. This is easy, just delete `/etc/sudoers.d/010_pi-nopasswd` .

Also, it would be awesome if the Raspberrys date is correct so set the correct timezone:

```bash
sudo timedatectl set-timezone <your_time_zone>
```

For my last trick, I will make some changes to harden the system a bit. The home directory of the `pi` user is world readable so let’s change that:

```bash
chmod 0750 /home/pi
```

And since we added a SSH key to the Raspberrys for SSH authentication I will disable the access through SSH using password and also won’t allow `root` user login. Adding this lines to `/etc/ssh/sshd_config` and reloading the `sshd` service will do:

```
PermitRootLogin no
UsePAM no
PasswordAuthentication no
```

### Installing Kubernetes

The Kubernetes version I will be installing is K3S:

<figure><a href="https://k3s.io/" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">Lightweight Kubernetes</div><div class="bookmark-description">The above figure shows the difference between K3s server and K3s agent nodes. For more information, see the architecture documentation. We are a Cloud Native Computing Foundation sandbox project.</div></div><div class="bookmark-href"><img src="https://k3s.io/favicon.ico" class="icon bookmark-icon"/>https://k3s.io/</div></div></a></figure>

Should include all the normal Kubernetes features but in a more optimized way. The installation is pretty easy to do actually, it is documented very well in the K3S page and the only thing you have to do is to run an installation script in each node of the cluster.

The only thing to keep in mind is that you have to start with the installation of the master node (By default K3S won’t allow you to have more than one) to get a secret token you need for the worker nodes installation.

By default the K3S script will deploy some components to the cluster, for a basic testing environment this is ok but if you want to customize this components configuration you need to tell K3S to not deploy them to avoid getting your configuration getting overwrited in every reboot.

This page shows what parameters to use in order to customize the installation:

<figure><a href="https://rancher.com/docs/k3s/latest/en/installation/install-options/server-config/" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">K3s Server Configuration Reference</div><div class="bookmark-description">In this section, you&#x27;ll learn how to configure the K3s server. Throughout the K3s documentation, you will see some options that can be passed in as both command flags and environment variables. For help with passing in options, refer to How to Use Flags and Environment Variables.</div></div><div class="bookmark-href"><img src="https://rancher.com/docs/img/favicon.png" class="icon bookmark-icon"/>https://rancher.com/docs/k3s/latest/en/installation/install-options/server-config/</div></div><img src="https://rancher.com/docs/img/logo-square.png" class="bookmark-image"/></a></figure>

Before starting with the installation I will add this parameters into the `/boot/cmdline.txt` file of every Pi to make sure the containers works as expected:

```
cgroup_memory=1 cgroup_enable=memory
```

#### Master node

Now we are ready to install K3S in the master node. Since I want to use Prometheus to get the metrics from the nodes instead of the typical Kubenretes metric-server and modify how the ingress controller (Traefik) is configured I will use `-no-deploy metrics-server,traefik` to tell K3S to not deploy those components:

```bash
./k3s_install.sh --no-deploy metrics-server,traefik
```

Once this finished, make sure you get the token for the workers nodes: `/var/lib/rancher/k3s/server/node-token` and also the `kubeconfig` file to be able to manage your cluster: `/etc/rancher/k3s/k3s.yaml`.

#### Worker nodes

To add you workers node to the cluster just execute this:

```bash
K3S_URL=https://<MASTER-NODE-IP>:6443
K3S_TOKEN=<TOKEN>
./k3s_install.sh
```

### Storage provisioning

For persistent volume provisioning I don’t really want to rely in the local path provider that K3S use by default. The problem with that provider is that if a pod is re-scheduled in a different node it won’t be able to access the persistent volume data because that volume is in another node. In order to avoid this problems, I will prepare a NFS server in the original Raspberry Pi I talked you about before and configure a NFS provider in the cluster that points to that server. The NFS server could be in one of the cluster nodes aswell if you don’t have another host to use.

#### NFS server installation

To be honest the configuration of the a NFS server was easier than I expected. Just install `nfs-kernel-server` package and prepare a share folder to use.

In the `/etc/exports` is where you have to configure the share for NFS and also that IPs addreses can access it. I will let here a little example:

```
/home/pi/Shared MASTER_IP(rw,fsid=0,all_squash,async,no_subtree_check,anonuid=1000,anongid=1000) WORKER1_IP(rw,fsid=0,all_squash,async,no_subtree_check,anonuid=1000,anongid=1000) WORKER2_IP(rw,fsid=0,all_squash,async,no_subtree_check,anonuid=1000,anongid=1000)
```

Make sure to run `sudo exportfs -ra` to update NFS exports and also to check that `nfs-server` and `rpc-statd.service` are running.

### Cluster configuration

#### Taints and labels

So we have a Kubernetes cluster but it needs a bit of tweaking

![checkNodes](/assets/images/Projects/MAGI_Project/checkNodes.png)

First of all, since I have 3 nodes I want to taint and label the master node to control what applications can be scheduled to it:

```bash
kubectl taint nodes melchior CriticalAddonsOnly:NoSchedule
kubectl label node melchior node-type=master
```

I used that taint because I noticed that all the addons (That is the name K3S use for all the manifests that are put in the `/var/lib/rancher/k3s/server/manifests` folder for deployment) deployed by K3S use that toleration. The label is one I invented.

Tainting the master node will give me control over what pods are scheduled into the master node. The idea is to only allow critical application to be in the master node, this way the master node will be more protected against resource intensive applications that can cause a node to crash.

#### NFS storage provider

I will use this NFS provider:

<figure><a href="https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">GitHub - kubernetes-sigs/nfs-subdir-external-provisioner</div><div class="bookmark-description">NFS subdir external provisioner is an automatic provisioner that use your existing and already configured NFS server to support dynamic provisioning of Kubernetes Persistent Volumes via Persistent Volume Claims. Persistent volumes are provisioned as ${namespace}-${pvcName}-${pvName}. Note: This repository is migrated from https://github.com/kubernetes-incubator/external-storage/tree/master/nfs-client.</div></div><div class="bookmark-href"><img src="https://github.com/favicon.ico" class="icon bookmark-icon"/>https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner</div></div><img src="https://opengraph.githubassets.com/4a2dbaf767d197f27c33cb75833f8b2e416212aa24818be2855f2ac818b2dae0/kubernetes-sigs/nfs-subdir-external-provisioner" class="bookmark-image"/></a></figure>

Since it offers the installation through Helm and K3S accepts Helm as a way of deploying an addon, just copying this file to `/var/lib/rancher/k3s/server/manifests` will be enough:

```yaml
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: nfs-storage
  namespace: kube-system
spec:
  chart: nfs-subdir-external-provisioner
  repo: https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner
  targetNamespace: kube-system
  set:
    nfs.server: NFS-SERVER-IP
    nfs.path: NFS-SHARE-PATH
    storageClass.name: nfs-storage
    storageClass.accessModes: ReadWriteMany
    storageClass.reclaimPolicy: Retain
    storageClass.archiveOnDelete: "false"
    storageClass.defaultClass: "true"
  valuesContent: |-
    nodeSelector:
      node-type: master
    tolerations:
    - key: CriticalAddonsOnly
      operator: Exists
      effect: NoSchedule
```

Notice that I added the needed tolerations and node selector configuration to force Kubernetes to schedule the provider into the master node.

After a bit, K3S will deploy all the components of the provider, including a storage class called  `nfs-storage`. This storage class is marked as default but since the pre-installed K3S storage class called `local-storage` is also marked as default there are 2 options:

- Delete the `local-storage` storage class
- Edit the `local-storage` storage class to make it non default

#### Traefik custom install

The reason why I decided to install Traefik by hand is because by default it won’t be able to get the real IP address of the clients because of the Traefik LoadBalancer configuration.

Before you ask, K3S use something called Klipper to create a load balancers inside the cluster. Normally a load balancer is deployed outside but K3S do it this way to allow the usage of load balancer services easier.

Adding `externalTrafficPolicy: Local`  ([More information](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip)) to the spec section of the Traefik service will solve the problem but if we let K3S deploy it, our changes won’t persist a reboot. Also I want to add a `nodeSelector` configuration to make sure Traefik is scheduled in the master node.

To install Traefik with this little configuration change I just took the `traefik.yaml` file that K3S normally uses and modified it a bit:

```bash
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: traefik-crd
  namespace: kube-system
spec:
  chart: https://%{KUBERNETES_API}%/static/charts/traefik-crd-10.3.001.tgz
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: traefik
  namespace: kube-system
spec:
  chart: https://%{KUBERNETES_API}%/static/charts/traefik-10.3.001.tgz
  set:
    global.systemDefaultRegistry: ""
  valuesContent: |-
    service:
      spec:
        externalTrafficPolicy: Local
    rbac:
      enabled: true
    ports:
      websecure:
        tls:
          enabled: true
    podAnnotations:
      prometheus.io/port: "8082"
      prometheus.io/scrape: "true"
    providers:
      kubernetesIngress:
        publishedService:
          enabled: true
    priorityClassName: "system-cluster-critical"
    image:
      name: "rancher/mirrored-library-traefik"
    nodeSelector:
      node-type: master
    tolerations:
    - key: "CriticalAddonsOnly"
      operator: "Exists"
    - key: "node-role.kubernetes.io/control-plane"
      operator: "Exists"
      effect: "NoSchedule"
    - key: "node-role.kubernetes.io/master"
      operator: "Exists"
      effect: "NoSchedule"
```

And why would I want to do all this may you ask? Why I need the real IP of the clients? Simple, for IP filtering. Using ingresses to access the services in the cluster is great so to expose something to the internet make sense to expose the Traefik LoadBalancer and make Traefik handle the requests. The problem of this approach is that anyone from the internet could reach private services what is not good.

With the configuration change I made, now I can create a traefik middleware for all the ingresses I want to be private to prevent traffic from the internet to go to them:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: private
  namespace: kube-system
spec:
  ipWhiteList:
    sourceRange:
      - 127.0.0.1/32
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
```

The only thing left is asking Traefik to use it where I want. Just adding this to the metadata section of the Ingresses I don’t want to be accesible from the internet will do: 

```yaml
annotations:
    traefik.ingress.kubernetes.io/router.middlewares: kube-system-private@kubernetescrd
```

Now the trafic to public services from the internet will pass through the ingress controller but if someone tries to get into a private service will get a Forbidden error message. This configuration is not the best for load balancing but is what I found to expose Traefik.

I added to the k3s-pi-cluster playbook a variable to change the `externalTrafficPolicy` option to `Local` or `Cluster` to let the playbook user decide what are its needs. Later I will explain a bit about how I ended up avoiding to expose Traefik to the internet and therefore using Traefik with the `externalTrafficPolicy` option set to `Cluster` as the default Trarfik configuration use.

#### Monitoring

Since my idea is to have this cluster working 24/7 I need a monitoring solution that can alert me of something happens. I want to use the Prometheus, Alert Manager and Grafana stack for this (Prometheus will be used as metrics API instead of metric-server for thins like scaling pods).

The official repository doesn’t really support the installation on Raspberry Pi at the moment of writting but this repository do:

<figure><a href="https://github.com/carlosedp/cluster-monitoring" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">GitHub - carlosedp/cluster-monitoring</div><div class="bookmark-description">The Prometheus Operator for Kubernetes provides easy monitoring definitions for Kubernetes services and deployment and management of Prometheus instances. This have been tested on a hybrid ARM64 / X84-64 Kubernetes cluster deployed as this article. This repository collects Kubernetes manifests, Grafana dashboards, and Prometheus rules combined with documentation and scripts to provide easy to operate end-to-end Kubernetes cluster monitoring with Prometheus using the Prometheus Operator.</div></div><div class="bookmark-href"><img src="https://github.com/favicon.ico" class="icon bookmark-icon"/>https://github.com/carlosedp/cluster-monitoring</div></div><img src="https://opengraph.githubassets.com/262a15cdb28fb73545a855c8c410a3f6e43d04186899dfa7dfdad20bc6e9ebb4/carlosedp/cluster-monitoring" class="bookmark-image"/></a></figure>

Cheers to the author because is awesome and works like a charm. Just follow the `README` file to install it in a K3S cluster. You want to follow the procedure in the master node, ensure openshift Python 3 library is installed.

Once everything is installed you should be able to acces Prometheus ,Grafana and Alert Manager. Just check the ingresses information to know where to access the services, this is how Grafana looks (Yeah the picture is one week after configuring all):

![grafana](/assets/images/Projects/MAGI_Project/grafana.png)

Since I don’t think that I will be using Prometheus and Alert Manager much I will just delete the ingresses to them and use kubectl port-forward to access them instead of having them open to the network.

I created a Telegram bot and configured Grafana to send alerts to me using it. It works incredibly well.

#### Network Policies

Checking K3S documentation I noticed that the default [CNI](https://github.com/containernetworking/cni) was Flannel. Flannel is really cool because is pretty fast but is not able to handle network policies. I really want to limit the conections a pod can do, specially if the pod is accessed from the internet. I normally edit the iptables rules in my Raspberry Pi to handle this restrictions in Docker but since Kubernetes has network policies to handle this stuff I want to use them.

I researched my options here and I found this post about installing Canal: 

<figure><a href="https://dev.to/jmarhee/network-policies-with-canal-and-flannel-on-k3s-11oe" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">Network Policies with Canal and Flannel on K3s</div><div class="bookmark-description">Flannel is a popular Container Network Interface (CNI) addon for Kubernetes, however, it does not provide (because it is Layer 3 network focused on transport between hosts, rather than container networking with the host) robust support for NetworkPolicy resources. Now, the policy features from another popular CNI, Calico, can be imported to Flannel using Canal.</div></div><div class="bookmark-href"><img src="https://res.cloudinary.com/practicaldev/image/fetch/s--E8ak4Hr1--/c_limit,f_auto,fl_progressive,q_auto,w_32/https://dev-to.s3.us-east-2.amazonaws.com/favicon.ico" class="icon bookmark-icon"/>https://dev.to/jmarhee/network-policies-with-canal-and-flannel-on-k3s-11oe</div></div><img src="https://dev.to/social_previews/article/944758.png" class="bookmark-image"/></a></figure>

The idea here is to keep using Flannel as CNI but install Calico as Network Policy manager.

The installation is pretty easy, just get the manifest:

[](https://docs.projectcalico.org/manifests/canal.yaml)

And search the environment variable called `CALICO_IPV4POOL_CIDR` that is commented. Since I’m installing Canal in K3S I need to uncomment the variable and set its value to `10.42.0.0/16`, what is the default Pod CIDR that K3S uses.

Just a quick note, during the installation the Canal pods were failing to start. The solution was to delete the `flannel.1` interface in every node with:

```bash
sudo ip link delete flannel.1
```

The pods started without problems afterwards.

I don’t really know if it was a problem I had because of all the things I tested before the installation or something that need to be done when installing Canal and Flannel is already running.

#### Handling certificates and application security

Last thing I need to finish the migration to Kubernetes is an easy way for issuing and managing TLS certificates and some kind of WAF. The solution I found to have this kind of stuff in Docker was this image:

<figure><a href="https://hub.docker.com/r/linuxserver/swag" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">Docker Hub</div><div class="bookmark-description">SWAG - Secure Web Application Gateway (formerly known as letsencrypt, no relation to Let's Encrypt™) sets up an Nginx webserver and reverse proxy with php support and a built-in certbot client that automates free SSL server certificate generation and renewal processes (Let's Encrypt and ZeroSSL). It also contains fail2ban for intrusion prevention.</div></div><div class="bookmark-href"><img src="https://hub.docker.com/favicon.ico" class="icon bookmark-icon"/>https://hub.docker.com/r/linuxserver/swag</div></div></a></figure>

Basically is Nginx, Certbot and Fail2ban working toguether. Kubernetes could work well with this solution using the `externalTrafficPolicy: Local` option in the Traefik load balancer to block the real IP address of the clients. The things is that, this is not something I want to use because doesn’t really scale well, the certificate management is pretty poor and I would need some kind of dashboard to really check what Fail2ban was doing.

For certificates the easier approach is to use cert-manager:

<figure><a href="https://cert-manager.io/docs/" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">cert-manager</div><div class="bookmark-description">cert-manager adds certificates and certificate issuers as resource types in Kubernetes clusters, and simplifies the process of obtaining, renewing and using those certificates. It can issue certificates from a variety of supported sources, including Let&#x27;s Encrypt, HashiCorp Vault, and Venafi as well as private PKI.</div></div><div class="bookmark-href"><img src="https://cert-manager.io/favicons/favicon.ico" class="icon bookmark-icon"/>https://cert-manager.io/docs/</div></div></a></figure>

The manifest need a little tweak to work with ARM, it is necessary to look for all the images used and add `-arm` at the end of all the image names. For example, if the image is `image:1.0` it is changed to `image-arm:1.0`. With that changes I was able to install cert-manager without problems.

Only one thing left for certificates, cert-manager need you to configure issuers to know how and where to ask for certificates. You can check how to create an Issuer in the cert-manager documentation.

I created an issuer with the  `ClusterIssuer` kind instead of the `Issuer`, because that way, the Issuer would be able to work in all the namespaces, and Let’s Encrypt  as the issuer to use. This issuer was configured to use a HTTP challenge in the port 80 that allows Let’s Encrypt to verify that the domain is mine.

I will show you what changes to make to an ingress to ask for a certificates to the configured issuer:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
  annotations:
    cert-manager.io/cluster-issuer: ISSUER-NAME # This
spec:
  rules:
  - host: app.com
    http:
      paths:
      - backend:
          service:
            name: app
            port:
              number: 80
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - app.com
    secretName: SECRET-NAME-FOR-CERT # This
```

The secret name can be anything you want really but please, use a proper name to know what the secret contains.

I had some problems to make this work because I was using really strict network policies and I forgot to allow the cert-manager pod to have ingress connections to the port 80 for the http challenge.

If the certificate is issued correctly you should be able to see that the certificate is ready executing this:

```bash
pi@raspberrypi:~ $ kubectl get certificate -n app
NAME                   READY   SECRET                 AGE
app-ingress-cert       True    app-ingress-cert       2s
```

Also you should be able to see that the certificate is valid visiting the site. I only have a problem know, no Fail2ban in front of the services facing the internet. 

The first thing I tried was to use Cloudflare proxying to filter the traffic. This works great but you should also filter the IPs that enter your network to only allow Cloudflare IPs to avoid attackers trying to bypass the Cloudflare protection. While checking for the Cloudflare IPs is when I found my favourite solution until now: 

<figure><a href="https://github.com/cloudflare/cloudflared" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">GitHub - cloudflare/cloudflared</div><div class="bookmark-description">Contains the command-line client for Cloudflare Tunnel, a tunneling daemon that proxies traffic from the Cloudflare network to your origins. This daemon sits between Cloudflare network and your origin (e.g. a webserver). Cloudflare attracts client requests and sends them to you via this daemon, without requiring you to poke holes on your firewall --- your origin can remain as closed as possible.</div></div><div class="bookmark-href"><img src="https://github.com/favicon.ico" class="icon bookmark-icon"/>https://github.com/cloudflare/cloudflared</div></div><img src="https://opengraph.githubassets.com/51b16e5228ccc817a729b6456db19de921d5ccaa647faee0acf7c7768b6607f7/cloudflare/cloudflared" class="bookmark-image"/></a></figure>

This thing is just awesome, it allows you to create a tunnel between Cloudflare and you to avoid opening ports in the router or firewall. This actually fix another problem I  have that I didn’t tell you about yet, my ISP blocks port 443 because apparently they use it for maintenance so for hosting the web services I have to use weird port numbers in the URLs. With Cloudflared the Clouldflare bypass and the port problems are fixed. Hosting a website in the internet without open ports, ideal.

To use this system, the only thing really needed is a Cloudflare account and a domain. The rest is to follow the documentation to set it up correctly. I created a little Helm chart that will help if some of you wants to use this approach:

<figure><a href="https://github.com/anthares101/k3s-pi-cluster-charts/tree/master/cloudflared" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">GitHub - anthares101/k3s-pi-cluster-charts/cloudflared</div><div class="bookmark-description">A place for my Helm charts! Contribute to anthares101/k3s-pi-cluster-charts development by creating an account on GitHub.</div></div><div class="bookmark-href"><img src="https://github.com/favicon.ico" class="icon bookmark-icon"/>https://github.com/anthares101/k3s-pi-cluster-charts</div></div><img src="https://opengraph.githubassets.com/7044e1dfe81c940e6e18136248081ba4e4d4cee21d021591181bb7cdd0bf25b1/anthares101/k3s-pi-cluster-charts" class="bookmark-image"/></a></figure>

I almost forgot, remember the HTTP challenge I used for getting the certificates with cert-manager? Well if I close the router ports obviously this stops working, there is a solution though. Let’s Encrypt allows another method for validation and it is called `dns01` in cert-manager:

<figure><a href="https://cert-manager.io/docs/configuration/acme/dns01/cloudflare/" class="bookmark source"><div class="bookmark-info"><div class="bookmark-text"><div class="bookmark-title">Cloudflare</div><div class="bookmark-description">To use Cloudflare, you may use one of two types of tokens. API Tokens allow application-scoped keys bound to specific zones and permissions, while API Keys are globally-scoped keys that carry the same permissions as your account. API Tokens are recommended for higher security, since they have more restrictive permissions and are more easily revocable.</div></div><div class="bookmark-href"><img src="https://cert-manager.io/favicons/favicon.ico" class="icon bookmark-icon"/>https://cert-manager.io/docs/configuration/acme/dns01/cloudflare/</div></div></a></figure>

It is true that is not as easy to setup as the HTTP challenge but with this new approach that is just the way to go.

## Some tips

### Importing images to K3S

Trying to migrate an application I had that uses an image that was not in Dockerhub made me discover that it is possible to just import images to the K3S image store:

```bash
# Export an image from your Docker image store to a tar file
docker save --output test-app-v1.0.0.tar test-app:v1.0.0
# Import an image to the K3S image store in the node
sudo k3s ctr images import /home/ubuntu/test-app-v1.0.0.tar
```

The only bad thing is that, each node have its own image store so you have to import the image too all of them in order to avoid problems with scheduling.

I guess a much better solution could be to host my own image registry in the cluster o my Raspberry Pi but this works too.

### K3S snapshots

Using the default K3S database, sqlite, makes the creation of snapshots really simple. Just stop the K3S service and copy the entire `/var/lib/rancher/k3s/server` directory for restoration (Obviously after the copy, start the K3S service again).

## Last Thoughts

The journey was pretty long and I really had lot of problems to get some things exactly as I wanted. But now that everything is working I can say that the migration was really a success, my old Raspberry Pi can now just focus on essential applications that support my internal network like the Samba, Pihole and NFS servers and the cluster will handle all the rest of the stuff including all those services that I want to expose to the internet.

The management of exposed services with Kubernetes is much simplier using network policies and cert-manager and the addition of Cloudflared (I know I could use it in Docker too but let me be happy with it) fixing all the problems with the ports and giving me a WAF with a fancy dashboards is just perfect.

PD: Someone noticed the Evangelion references?
