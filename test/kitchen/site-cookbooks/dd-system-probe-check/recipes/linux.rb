
execute "df -Th" do
  command "df -Th /tmp"
  live_stream true
  action :run
  ignore_failure true
end

package 'growpart' do
  case node[:platform]
  when 'amazon', 'redhat', 'centos', 'fedora'
    package_name 'cloud-utils-growpart'
  else
    package_name 'cloud-guest-utils'
  end
end

#if Chef::SystemProbeHelpers::arm?(node) and node[:platform] == 'centos'
#  package 'cloud-utils-growpart'
#  package 'gdisk'

execute 'increase space' do
  command <<-EOF
    df -Th /tmp

    dev_name=$(df -Th / | tail -n1 | awk '{print $1}')
    fstype=$(df -Th / | tail -n1 | awk '{print $2}')
    use=$(df -Th / | tail -n1 | awk '{print $6}' | tr -d %)

    if [[ $use -lt 70 ]]; then
       exit 0
    fi

    if [[ ${dev_name} =~ ^/dev/mapper ]]; then
       lvresize -L +4G ${dev_name}
       resize2fs ${dev_name}
    fi
    if [[ ${dev_name} =~ ^/dev/nvme ]]; then
       disk=$(echo $dev_name | awk -Fp '{print $1}')
       partnum=$(echo $dev_name | awk -Fp '{print $2}')

       growpart ${disk} ${partnum}
       xfs_growfs -d /
    fi
    if [[ ${dev_name} =~ ^tmpfs ]]; then
       mount -o remount,size=10G /tmp
    fi

    df -Th /tmp
  EOF
  user "root"
  live_stream true
  ignore_failure true
end
#end

if platform?('centos')
  include_recipe '::old_vault'
end

case node[:platform]
  when 'ubuntu', 'debian'
    apt_update
end

execute "update yum repositories" do
  command "yum -y update"
  user "root"
  case node[:platform]
  when 'amazon'
    action :run
  else
    action :nothing
  end
end

kernel_version = `uname -r`.strip
package 'kernel headers' do
  case node[:platform]
  when 'redhat', 'centos', 'fedora', 'amazon'
    package_name "kernel-devel-#{kernel_version}"
  when 'ubuntu', 'debian'
    package_name "linux-headers-#{kernel_version}"
  end
end

package 'java' do
  case node[:platform]
  when 'redhat', 'centos', 'fedora', 'amazon'
    package_name 'java'
  when 'ubuntu', 'debian'
    package_name 'default-jre'
  end
end

package 'python3'

case node[:platform]
  when 'centos', 'redhat'
    package 'iptables'
end

package 'conntrack'

package 'netcat' do
  case node[:platform]
  when 'amazon'
    package_name 'nmap-ncat'
  when 'redhat', 'centos', 'fedora'
    package_name 'nc'
  else
    package_name 'netcat'
  end
end

package 'socat'

package 'wget'

package 'curl' do
  case node[:platform]
  when 'amazon'
    case node[:platform_version]
    when '2022'
      package_name 'curl-minimal'
    else
      package_name 'curl'
    end
  else
    package_name 'curl'
  end
end

package 'iptables'

# Enable IPv6 support
kernel_module 'ipv6' do
  action :load
end
execute 'sysctl net.ipv6.conf.all.disable_ipv6=0'


execute 'ensure conntrack is enabled' do
  command "iptables -I INPUT 1 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT"
  user "root"
  action :run
end



execute 'increase spaceallos' do
  command <<-EOF
    df -h /tmp

    df -h /tmp
  EOF
  user "root"
  live_stream true
  ignore_failure true
end

execute 'disable firewalld on redhat' do
  command "systemctl disable --now firewalld"
  user "root"
  ignore_failure true
  case node[:platform]
  when 'redhat'
    action :run
  else
    action :nothing
  end
end

directory "/opt/datadog-agent/embedded/bin" do
  recursive true
end

directory "/opt/datadog-agent/embedded/include" do
  recursive true
end

directory "/tmp/system-probe-tests/pkg/ebpf/bytecode/build/co-re/btf" do
  recursive true
end

cookbook_file "/opt/datadog-agent/embedded/bin/clang-bpf" do
  source "clang-bpf"
  mode '0744'
  action :create
end

cookbook_file "/opt/datadog-agent/embedded/bin/llc-bpf" do
  source "llc-bpf"
  mode '0744'
  action :create
end

cookbook_file "/tmp/system-probe-tests/pkg/ebpf/bytecode/build/co-re/btf/minimized-btfs.tar.xz" do
  source "minimized-btfs.tar.xz"
  action :create
end

directory "/go/bin" do
  recursive true
end

cookbook_file "/go/bin/gotestsum" do
  source "gotestsum"
  mode '0744'
  action :create
end

cookbook_file "/go/bin/test2json" do
  source "test2json"
  mode '0744'
  action :create
end

directory "/tmp/junit" do
  recursive true
end

cookbook_file "/tmp/junit/job_url.txt" do
  source "job_url.txt"
  mode '0444'
  action :create
  ignore_failure true
end

cookbook_file "/tmp/junit/tags.txt" do
  source "tags.txt"
  mode '0444'
  action :create
  ignore_failure true
end

directory "/tmp/testjson" do
  recursive true
end

directory "/tmp/pkgjson" do
  recursive true
end

# Install relevant packages for docker
include_recipe "::docker_installation"

remote_directory "/tmp/kitchen-dockers" do
  source 'dockers'
  files_owner 'root'
  files_group 'root'
  files_mode '0750'
  action :create
  recursive true
end

# Load docker images
execute 'install docker-compose' do
  cwd '/tmp/kitchen-dockers'
  command <<-EOF
    for docker_file in $(ls); do
      echo docker load -i $docker_file
      docker load -i $docker_file
      rm -rf $docker_file
    done
  EOF
  user "root"
  live_stream true
end



execute "df -hafter" do
  command "df -Th"
  live_stream true
  action :run
  ignore_failure true
end
