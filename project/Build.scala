import sbt._
import Keys._
import play.Project._

object ApplicationBuild extends Build {

    val appName         = "play-jaas"
    val appVersion      = "1.1.0"

    val appDependencies = Seq(
        javaCore
    )

    val main = play.Project(appName, appVersion, appDependencies).settings(
    )

}
