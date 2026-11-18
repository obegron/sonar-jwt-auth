FROM sonarqube:26.10.0.133078-community
COPY --chown=sonarqube:sonarqube sonarqube-community-branch-plugin-26.10.0.jar /opt/sonarqube/extensions/plugins/
# Not a SonarQube plugin: a javaagent jar that carries a CoreExtension (loaded from the system classpath)
COPY --chown=sonarqube:sonarqube sonar-jwt-auth.jar /opt/sonarqube/extensions/sonar-jwt-auth.jar
