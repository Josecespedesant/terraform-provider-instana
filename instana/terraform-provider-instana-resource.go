package instana

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/gessnerfl/terraform-provider-instana/instana/restapi"
	"github.com/gessnerfl/terraform-provider-instana/utils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// ResourceMetaData the metadata of a terraform ResourceHandle
type ResourceMetaData struct {
	ResourceName     string
	Schema           map[string]*schema.Schema
	SchemaVersion    int
	SkipIDGeneration bool
	ResourceIDField  *string
}

// ResourceHandle resource specific implementation which provides metadata and maps data from/to terraform state. Together with TerraformResource terraform schema resources can be created
type ResourceHandle[T restapi.InstanaDataObject] interface {
	//MetaData returns the metadata of this ResourceHandle
	MetaData() *ResourceMetaData
	//StateUpgraders returns the slice of state upgraders used to migrate states from one version to another
	StateUpgraders() []schema.StateUpgrader

	//GetRestResource provides the restapi.RestResource used by the ResourceHandle
	GetRestResource(api restapi.InstanaAPI) restapi.RestResource[T]
	//UpdateState updates the state of the resource provided as schema.ResourceData with the input data from the Instana API provided as restapi.InstanaDataObject
	UpdateState(d *schema.ResourceData, obj T, formatter utils.ResourceNameFormatter) error
	//MapStateToDataObject maps the current state of the resource provided as schema.ResourceData to the API model of the Instana API represented as an implementation of restapi.InstanaDataObject
	MapStateToDataObject(d *schema.ResourceData, formatter utils.ResourceNameFormatter) (T, error)
	//SetComputedFields calculate and set the calculated value of computed fields of the given resource
	SetComputedFields(d *schema.ResourceData) error
}

// NewTerraformResource creates a new terraform resource for the given handle
func NewTerraformResource[T restapi.InstanaDataObject](handle ResourceHandle[T]) TerraformResource {
	return &terraformResourceImpl[T]{
		resourceHandle: handle,
	}
}

// TerraformResource internal simplified representation of a Terraform resource
type TerraformResource interface {
	Create(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics
	Read(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics
	Update(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics
	Delete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics
	ToSchemaResource() *schema.Resource
}

type terraformResourceImpl[T restapi.InstanaDataObject] struct {
	resourceHandle ResourceHandle[T]
}

// Create defines the create operation for the terraform resource
func (r *terraformResourceImpl[T]) Create(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	providerMeta := meta.(*ProviderMeta)
	instanaAPI := providerMeta.InstanaAPI

	if !r.resourceHandle.MetaData().SkipIDGeneration {
		d.SetId(RandomID())
	}
	err := r.resourceHandle.SetComputedFields(d)
	if err != nil {
		return diag.FromErr(err)
	}

	createRequest, err := r.resourceHandle.MapStateToDataObject(d, providerMeta.ResourceNameFormatter)
	if err != nil {
		return diag.FromErr(err)
	}
	createdObject, err := r.resourceHandle.GetRestResource(instanaAPI).Create(createRequest)
	if err != nil {
		return diag.FromErr(err)
	}
	err = r.resourceHandle.UpdateState(d, createdObject, providerMeta.ResourceNameFormatter)
	if err != nil {
		return diag.FromErr(err)
	}
	return nil
}

// Read defines the read operation for the terraform resource
func (r *terraformResourceImpl[T]) Read(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	providerMeta := meta.(*ProviderMeta)
	instanaAPI := providerMeta.InstanaAPI
	resourceID := r.getResourceID(d)
	if len(resourceID) == 0 {
		return diag.FromErr(fmt.Errorf("resource ID of %s is missing", r.resourceHandle.MetaData().ResourceName))
	}
	obj, err := r.resourceHandle.GetRestResource(instanaAPI).GetOne(resourceID)
	if err != nil {
		if errors.Is(err, restapi.ErrEntityNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	err = r.resourceHandle.UpdateState(d, obj, providerMeta.ResourceNameFormatter)
	if err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func (r *terraformResourceImpl[T]) getResourceID(d *schema.ResourceData) string {
	if r.resourceHandle.MetaData().ResourceIDField != nil {
		return d.Get(*r.resourceHandle.MetaData().ResourceIDField).(string)
	}
	return d.Id()
}

// Update defines the update operation for the terraform resource
func (r *terraformResourceImpl[T]) Update(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	providerMeta := meta.(*ProviderMeta)
	instanaAPI := providerMeta.InstanaAPI

	obj, err := r.resourceHandle.MapStateToDataObject(d, providerMeta.ResourceNameFormatter)
	if err != nil {
		return diag.FromErr(err)
	}
	updatedObject, err := r.resourceHandle.GetRestResource(instanaAPI).Update(obj)
	if err != nil {
		return diag.FromErr(err)
	}
	err = r.resourceHandle.UpdateState(d, updatedObject, providerMeta.ResourceNameFormatter)
	if err != nil {
		return diag.FromErr(err)
	}
	return nil
}

// Delete defines the delete operation for the terraform resource
func (r *terraformResourceImpl[T]) Delete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	providerMeta := meta.(*ProviderMeta)
	instanaAPI := providerMeta.InstanaAPI

	object, err := r.resourceHandle.MapStateToDataObject(d, providerMeta.ResourceNameFormatter)
	if err != nil {
		return diag.FromErr(err)
	}
	err = r.resourceHandle.GetRestResource(instanaAPI).DeleteByID(object.GetIDForResourcePath())
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func (r *terraformResourceImpl[T]) ToSchemaResource() *schema.Resource {
	metaData := r.resourceHandle.MetaData()
	return &schema.Resource{
		CreateContext: r.Create,
		ReadContext:   r.Read,
		Importer: &schema.ResourceImporter{
			StateContext: r.importState,
		},
		UpdateContext:  r.Update,
		DeleteContext:  r.Delete,
		Schema:         metaData.Schema,
		SchemaVersion:  metaData.SchemaVersion,
		StateUpgraders: r.resourceHandle.StateUpgraders(),
	}
}

func (r *terraformResourceImpl[T]) importState(_ context.Context, d *schema.ResourceData, _ interface{}) ([]*schema.ResourceData, error) {
	if r.resourceHandle.MetaData().ResourceIDField != nil {
		err := d.Set(*r.resourceHandle.MetaData().ResourceIDField, d.Id())
		if err != nil {
			return []*schema.ResourceData{}, err
		}
	}
	return []*schema.ResourceData{d}, nil
}
