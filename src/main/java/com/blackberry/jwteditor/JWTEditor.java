/*
Author : Fraser Winterborn

Copyright 2021 BlackBerry Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.blackberry.jwteditor;

import com.blackberry.jwteditor.presenter.PresenterStore;
import com.blackberry.jwteditor.utils.PEMUtils;
import com.blackberry.jwteditor.utils.Utils;
import com.blackberry.jwteditor.view.StandaloneView;
import com.nimbusds.jose.jwk.JWK;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;

public class JWTEditor {

    public static void main(String[] argv){
        Security.addProvider(new BouncyCastleProvider());

        // If no arguments are provided, show the GUI
        if(argv.length == 0){
            gui();
        }
        // Otherwise, use the CLI parser
        else {
            ArgumentParser parser = ArgumentParsers.newFor(Utils.getResourceString("tool_name"))
                    .build()
                    .defaultHelp(true);

            // First argument - mode (gui/convert)
            Subparsers subparsers = parser.addSubparsers().dest("mode"); //NON-NLS

            // gui mode subparser
            subparsers.addParser("gui").help(Utils.getResourceString("args_run_gui")); //NON-NLS

            // convert mode subparser
            Subparser convert_group = subparsers.addParser("convert").help(Utils.getResourceString("args_convert")); //NON-NLS
            convert_group.addArgument("key_file").required(true).help(Utils.getResourceString("args_convert_key_file")); //NON-NLS
            convert_group.addArgument("--kid").required(false).help(Utils.getResourceString("args_convert_kid")); //NON-NLS

            // Try to parse the CLI arguments
            Namespace args = null;
            try {
                args = parser.parseArgs(argv);
            } catch (ArgumentParserException e) {
                parser.handleError(e);
                System.exit(1);
            }

            // Call appropriate handler function based on provided mode
            switch(args.getString("mode")){ //NON-NLS
                case "gui"://NON-NLS
                    gui();
                    break;
                case "convert"://NON-NLS
                    convert(args);
                    break;
                default:
                    break;
            }

        }
    }

    /**
     * gui mode handler
     */
    private static void gui(){
        // Create a new window, load and display the StandaloneView
        JFrame frame = new JFrame(Utils.getResourceString("tool_name"));
        StandaloneView standaloneView = new StandaloneView(frame, new PresenterStore());
        frame.getContentPane().add(standaloneView.getPanel());
        frame.setMinimumSize(new Dimension(1000,700));
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    /**
     * convert mode handler
     * @param args the parsed command-line arguments
     */
    private static void convert(Namespace args){

        // Try to open the file path provided via the cli
        String pemFileContents = null;
        try {
            pemFileContents = new String(Files.readAllBytes(Paths.get(args.getString("key_file")))); //NON-NLS
        }
        catch(IOException e) {
            System.err.println(Utils.getResourceString("error_convert_invalid_file"));
            System.exit(1);
        }

        // Get the key ID provided via the cli
        String kid = args.getString("kid");//NON-NLS

        // Try to do an RSA key conversion
        JWK jwk = null;
        try {
            if(kid == null){
                jwk = PEMUtils.pemToRSAKey(pemFileContents);
            }
            else {
                jwk = PEMUtils.pemToRSAKey(pemFileContents, kid);
            }
        } catch (PEMUtils.PemException e) {
            // Not an RSA key
        }

        // Try to do an EC key conversion
        try {
            if(kid == null){
                jwk = PEMUtils.pemToECKey(pemFileContents);
            }
            else {
                jwk = PEMUtils.pemToECKey(pemFileContents, kid);
            }
        } catch (PEMUtils.PemException e) {
            // Not an EC key
        }

        // Try to do an OKP conversion
        try {
            if(kid == null){
                jwk = PEMUtils.pemToOctetKeyPair(pemFileContents);
            }
            else {
                jwk = PEMUtils.pemToOctetKeyPair(pemFileContents, kid);
            }
        } catch (PEMUtils.PemException e) {
            // Not a valid OKP
        }

        // If all conversions failed, display an error
        if(jwk == null){
            System.err.println(Utils.getResourceString("error_convert_invalid_pem"));
            System.exit(1);
        }

        // Otherwise, print the private and public key if available, or just the public key
        if(jwk.isPrivate()){
            System.out.printf("============ %s ============%n", Utils.getResourceString("private_key")); //NON-NLS
            System.out.println(Utils.prettyPrintJSON(jwk.toJSONString()));
            System.out.printf("============ %s ============%n", Utils.getResourceString("public_key")); //NON-NLS
            System.out.println(Utils.prettyPrintJSON(jwk.toPublicJWK().toJSONString()));
        }
        else {
            System.out.printf("============ %s ============%n", Utils.getResourceString("public_key")); //NON-NLS
            System.out.println(Utils.prettyPrintJSON(jwk.toJSONString()));
        }
    }
}
