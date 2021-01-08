package org.whispersystems.witness


import org.gradle.api.InvalidUserDataException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.Configuration
import org.gradle.api.artifacts.ResolvedArtifact
import org.gradle.api.plugins.JavaBasePlugin

import java.security.MessageDigest

class WitnessPluginExtension {
    List<String> verify
    List<String> includeConfigurations
}

class WitnessPlugin implements Plugin<Project> {

    static String calculateSha256(file) {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        file.eachByte 4096, { bytes, size ->
            md.update(bytes, 0, size);
        }
        return md.digest().collect { String.format "%02x", it }.join();
    }

    void apply(Project project) {
        boolean isRoot = project == project.rootProject;

        if (!isRoot) {
            project.logger.info("Witness plugin will only be applied the root project of a multi-project build.")
            return
        }

        project.extensions.create("dependencyVerification", WitnessPluginExtension)
        project.dependencyVerification.includeConfigurations = ['compileClasspath']

        project.task('calculateChecksums') {
            group = JavaBasePlugin.VERIFICATION_GROUP
            description = 'Calculates checksums of dependencies as prints on console.'

            doLast {

                println "dependencyVerification {"
                println "    verify = ["

                findResolvedArtifacts(project).stream()
                        .map({ it.moduleVersion.id.group + ":" + it.moduleVersion.id.name + ":" + it.moduleVersion.id.version + ":" + calculateSha256(it.file) })
                        .forEach({
                            println "        '" + it + "',"
                        })

                println "    ]"
                println "}"
            }
        }

        def verifyChecksums = project.task('verifyChecksums') {
            group = JavaBasePlugin.VERIFICATION_GROUP
            description = 'Verifies checksums of local dependencies and fails if any of them does not match.'

            doLast {
                verify(project)
            }
        }

        project.afterEvaluate {
            def checkTask = project.tasks.findByName('check')
            if (checkTask != null) {
                checkTask.dependsOn(verifyChecksums)
                checkTask.mustRunAfter(verifyChecksums)
            }
        }
    }

    static Collection<ResolvedArtifact> findResolvedArtifacts(Project project) {
        project.dependencyVerification.includeConfigurations.stream()
                .flatMap({ findEligibleConfigurations(project, it).stream() })
                .flatMap({ it.resolvedConfiguration.resolvedArtifacts.stream() })
                .distinct()
                .sorted(Comparator.comparing({ it.moduleVersion.toString() }))
                .filter({ it.file.exists() && !it.file.isDirectory() })
                .collect()
    }

    static Collection<Configuration> findEligibleConfigurations(Project project, String configName) {
        def eligibleProjects = project.subprojects.empty ? [project] : project.subprojects
        return eligibleProjects.stream()
                .filter({ it.configurations.findByName(configName) != null })
                .map({ it.configurations.getByName(configName) })
                .collect()
    }


    static void verify(Project project) {
        Collection<ResolvedArtifact> artifacts = findResolvedArtifacts(project)

        project.dependencyVerification.verify.each {
            assertion ->
                List parts = assertion.tokenize(":")
                String group = parts.get(0)
                String name = parts.get(1)
                String version = parts.get(2)
                String expectedHash = parts.get(3)

                project.logger.info("Verifying checksum of " + group + ":" + name + ":" + version + ":" + expectedHash)

                Collection<ResolvedArtifact> matchingDependencies = artifacts.stream()
                        .filter({ it.moduleVersion.id.group == group && it.moduleVersion.id.name == name && it.moduleVersion.id.version == version })
                        .collect()

                if (matchingDependencies.empty) {
                    throw new InvalidUserDataException("No dependency for integrity assertion found: " + group + ":" + name + ":" + version + ":" + expectedHash)
                }

                matchingDependencies.each {
                    def actualHash = calculateSha256(it.file)
                    if (expectedHash != actualHash) {
                        throw new InvalidUserDataException("Checksum failed for " + it.moduleVersion + ": expected '" + expectedHash + "' but was '" + actualHash + "'")
                    }
                }
        }
    }
}
