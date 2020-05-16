# git-checker

This script is designed to pull in a list of ec2 instances that are memebers security groups designed to expose them to the Internet on common web ports. Once it has the list, it checks that the instance has a public IP, and is currently in the 'running' state.
If the instance is running, and has a public IP it makes a request to the port to see if the .git directory is being hosted by a webserver on the instance.

This script is written to leverage Prisma, and push results to Splunk. Feel free to cut that code out and replace it with code that makes sense for your applications.

There are some gaps that could be improved here.

1. We're only checking an instance based on IP, if multiple websites are being hosted on the instance its possible we'll miss potentially exposed .git directories
2. We're only looking at ec2 instances. Ideally we should also be checking load balancers with similar configurations, and s3 buckets configured to host websites.
