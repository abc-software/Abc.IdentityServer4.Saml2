<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" ValidateRequest="false"
    Inherits="Samples.Saml.ServiceProvider._Default" %>

<%@ OutputCache Location="None" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Service Provider</title>
</head>
<body>
    <form id="DefaultForm" runat="server">
    <div style="font-size: x-large; font-weight: bold">
        Windows Identity Foundation - SAML Service Provider
    </div>
    <div>
        <br />
        You are now logged in using the SAML Protocol 
        <asp:Literal id="username" runat="server"></asp:Literal><br />
        <br />
        Click here to logout:
        <br />
        <asp:Button ID="Logout" runat="server" Text="Logout" OnClick="Logout_Click" />
    </div>
    </form>
</body>
</html>
