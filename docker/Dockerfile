# SonarQube Community Build with sonar-jwt-auth loaded as a javaagent.
# Build:  cp target/sonar-jwt-auth-*.jar docker/sonar-jwt-auth.jar && docker build -t sonarqube-jwt docker
# Already using another javaagent (e.g. sonarqube-community-branch-plugin)? Do not rely on this ENV: add this agent to your own
# SONAR_WEB_JAVAADDITIONALOPTS, see docs/INSTALL.md.
ARG SONAR_IMAGE=sonarqube:26.10.0.133078-community
FROM ${SONAR_IMAGE}
COPY --chown=sonarqube:sonarqube sonar-jwt-auth.jar /opt/sonarqube/extensions/sonar-jwt-auth.jar
ENV SONAR_WEB_JAVAADDITIONALOPTS="-javaagent:/opt/sonarqube/extensions/sonar-jwt-auth.jar=web"
