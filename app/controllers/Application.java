package controllers;

import play.mvc.Controller;
import play.mvc.Result;
import views.html.index;

/**
 * A non secured controller.
 *
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Nov 8, 2012 $
 */
public class Application extends Controller {

  public static Result index() {
      return ok(views.html.index.render());
  }

}